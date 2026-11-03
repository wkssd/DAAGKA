#ifndef IOT_NS3_PEER_H
#define IOT_NS3_PEER_H
#include "wire.h"
#include "append-pacer.h"
#include "daagka-crypto.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include <memory>
#include <random>
#include <ostream>
#include <iomanip>
#include <chrono>

using namespace ns3;
using namespace iotraft;
using namespace iotraft::wire;
struct Settings {
  uint32_t n = 3, coreNodes = 0, initiator = 0, seed = 17, rngRun = 1;
  bool stagedAgreement = false, olsr = false, cryptoAgreement = false;
  bool staticMobility = false, presetArp = false;
  uint64_t electionBase = 600, appendRetryMs = 0, appendRetryMaxMs = 1600;
  uint64_t appendPaceMs = 0;
  uint64_t compute = 10, duration = 10000, start = 100, retry = 200, gmStepMs = 500;
  double loss = 0, distance = 100, speed = 5, alpha = 0.85;
  std::string out;
};
static uint64_t NowMs() { return Simulator::Now().GetMilliSeconds(); }
static uint64_t NowNs() { return Simulator::Now().GetNanoSeconds(); }
static std::mt19937 Seeded(const Settings& c, uint32_t id, uint32_t domain) {
  std::seed_seq seed{c.seed, c.rngRun, id, domain};
  return std::mt19937(seed);
}
class Peer {
 public:
  Peer(uint32_t id, const Settings& c, const Ipv4InterfaceContainer& ips,
       Ptr<Node> node, std::ostream& events, std::ostream& transport)
      : id_(id), c_(c), ips_(ips), events_(events), transport_(transport), election_(Seeded(c, id, 1)),
        drop_(Seeded(c, id, 2)), serial_(0), lastRole_(Role::Follower),
        lastTerm_(0), committed_(false), read_(false), ready_(false), confirmed_(false),
        readMs_(0), nextRetry_(0), target_(0), confirmMs_(0), attempts_(0), tx_(0), txBytes_(0),
        rx_(0), rxBytes_(0), dropped_(0), rejected_(0), complete_(0), sendErrors_(0) {
    std::vector<NodeId> members;
    for (uint32_t i = 0; i < c.n; ++i) {
      if (!c.coreNodes || i < c.coreNodes) members.push_back(i);
      if (!c.cryptoAgreement) materials_.push_back(std::string(320, static_cast<char>(i + 1)));
    }
    if (!c.coreNodes || id < c.coreNodes) {
      raft_.reset(new Raft(id, members, c.electionBase, 100,
        [this](NodeId, Term, uint64_t base) { return base + election_() % base; }));
      raft_->setRetryPolicy(c.appendRetryMs, c.appendRetryMaxMs);
      raft_->setRpcObserver([this](const Message& m, const char* outcome) {
        transport_ << NowNs() << ',' << id_ << ",ack_" << outcome << ',' << m.from
                   << ',' << m.from << ",0," << m.matched << ',' << m.term << ','
                   << m.sequence << ',' << m.accepted << '\n';
      });
      raft_->setObserver([this](bool applied, bool majority, Index index, const Entry& entry) {
        if (entry.request.empty()) return;
        Event(applied ? "apply" : (majority ? "majority_commit" : "commit_index"),
              entry.request, index);
        if (applied && entry.request == "gka-single-1") committed_ = true;
      });
    }
    socket_ = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    if (socket_->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9000)) != 0)
      throw std::runtime_error("UDP bind failed");
    socket_->SetRecvCallback(MakeCallback(&Peer::Receive, this));
  }
  void ConfigureCrypto(const daagka::Bytes& session,
                       const std::vector<daagka::PublicMember>& roster,
                       std::unique_ptr<daagka::Member> member) {
    if (!c_.cryptoAgreement || !member || member->id != "uav-" + std::to_string(id_))
      throw std::invalid_argument("invalid cryptographic member");
    daagka::verify_roster(session, roster);
    session_ = session;
    cryptoRoster_ = roster;
    cryptoMember_ = std::move(member);
  }
  void Event(const std::string& what, const std::string& request = "gka-single-1", Index index = 0) {
    events_ << NowMs() << ',' << id_ << ',' << what << ',' << (raft_ ? raft_->term() : 0) << ','
            << (raft_ ? raft_->committed() : 0) << ',' << NowNs() << ',' << request << ',' << index
            << ',' << attempts_ << ',' << target_ << '\n';
  }
  void Transport(const char* action, uint32_t other, const Bytes& bytes, int status) {
    if (bytes.size() < FragmentHeader) return;
    Reader r(bytes); r.get(8); const uint64_t source = r.get(4), serial = r.get(8);
    const uint64_t total = r.get(4), part = r.get(2), count = r.get(2);
    transport_ << NowNs() << ',' << id_ << ',' << action << ',' << other << ','
               << source << ',' << serial << ',' << total << ',' << part << ',' << count
               << ',' << status << '\n';
  }
  void Send(uint32_t to, const Bytes& body) {
    std::vector<Bytes> parts = fragment(body, id_, ++serial_);
    std::string category = body[0] == 2 ? "client" : "confirmation";
    uint64_t term = 0, sequence = 0, repeated = 0;
    if (body[0] == 1) {
      Message m; Bytes wire(body.begin() + 1, body.end());
      if (!decode(wire, m)) throw std::runtime_error("outgoing decode failed");
      term = m.term; sequence = m.sequence;
      category = m.kind == Kind::Vote ? "vote" : m.kind == Kind::VoteReply ? "vote_reply" :
                 m.kind == Kind::AppendReply ? "append_reply" : "heartbeat";
      if (m.kind == Kind::Append) {
        if (!m.entries.empty()) category = "noop_append";
        for (size_t j = 0; j < m.entries.size(); ++j)
          if (!m.entries[j].request.empty()) category = "data_append";
        repeated = !appendSends_.insert(std::make_pair(to, std::make_pair(term, sequence))).second;
      }
    }
    transport_ << NowNs() << ',' << id_ << ",logical_" << category << ',' << to << ','
               << id_ << ',' << serial_ << ',' << body.size() << ',' << term << ','
               << sequence << ',' << repeated << '\n';
    for (size_t i = 0; i < parts.size(); ++i) {
      ++tx_; txBytes_ += parts[i].size();
      Ptr<Packet> packet = Create<Packet>(&parts[i][0], parts[i].size());
      transport_ << NowNs() << ',' << id_ << ",packet," << to << ',' << id_ << ',' << serial_
                 << ',' << packet->GetUid() << ',' << i << ',' << parts.size() << ",0\n";
      const int sent = socket_->SendTo(packet, 0,
            InetSocketAddress(ips_.GetAddress(to), 9000));
      Transport("send", to, parts[i], sent);
      if (sent < 0) ++sendErrors_;
    }
  }
  Bytes Client(uint8_t kind) {
    Bytes b; put(b, kind, 1);
    text(b, c_.stagedAgreement && kind == 2 && !selectionCommitted_ ? "gka-selection-1" : "gka-single-1");
    if (kind == 2) text(b, c_.stagedAgreement && !selectionCommitted_ ? selection_ : result_);
    return b;
  }
  std::string EncodeSelection(const daagka::Selection& item) const {
    Bytes b;
    text(b, item.leader);
    auto field = [&b](const daagka::Bytes& v) { text(b, std::string(v.begin(), v.end())); };
    field(item.z_public); field(item.key_commitment); field(item.digest);
    put(b, item.envelopes.size(), 4);
    for (const auto& envelope : item.envelopes) {
      text(b, envelope.recipient);
      field(envelope.nonce); field(envelope.ciphertext); field(envelope.tag);
    }
    field(item.proof.commitment); field(item.proof.response);
    return std::string(b.begin(), b.end());
  }
  daagka::Selection DecodeSelection(const std::string& encoded) const {
    Bytes b(encoded.begin(), encoded.end()); Reader r(b);
    auto field = [&r]() { const std::string s = r.text(); return daagka::Bytes(s.begin(), s.end()); };
    daagka::Selection item;
    item.leader = r.text();
    item.z_public = field(); item.key_commitment = field(); item.digest = field();
    const uint64_t n = r.get(4);
    if (n != c_.n) throw std::invalid_argument("wrong envelope count");
    for (uint64_t i = 0; i < n; ++i) {
      daagka::Envelope envelope;
      envelope.recipient = r.text();
      envelope.nonce = field(); envelope.ciphertext = field(); envelope.tag = field();
      item.envelopes.push_back(envelope);
    }
    item.proof.commitment = field(); item.proof.response = field();
    if (r.p != b.size()) throw std::invalid_argument("selection trailing bytes");
    return item;
  }
  void PrepareCryptoMaterial() {
    if (!c_.cryptoAgreement || !cryptoMember_ || !selectionCommitted_ || issued_) return;
    const auto started = std::chrono::steady_clock::now();
    issued_.reset(new daagka::Issued(daagka::issue(*cryptoMember_, session_, cryptoRoster_)));
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    Event("crypto_issue_done");
    cryptoIssueUs_ = static_cast<uint64_t>(elapsed);
    result_ = EncodeSelection(issued_->selection);
  }
  void Flush() {
    if (!raft_) return;
    if (c_.appendPaceMs) {
      const size_t removed = pacer_.prune([this](const Message& m) { return raft_->isPending(m); });
      if (removed) transport_ << NowNs() << ',' << id_ << ",pace_pruned,0," << id_
                             << ",0," << removed << ",0,0,0\n";
    }
    const std::vector<Message> messages = raft_->drain();
    for (size_t i = 0; i < messages.size(); ++i) {
      Bytes b = encode(messages[i]); b.insert(b.begin(), 1);
      bool business = false;
      for (const Entry& entry : messages[i].entries) business |= !entry.request.empty();
      if (c_.appendPaceMs && messages[i].kind == Kind::Append && business) {
        if (!raft_->isPending(messages[i])) continue;
        const auto result = pacer_.enqueue(messages[i], b);
        transport_ << NowNs() << ',' << id_ << ",pace_"
                   << (result == AppendPacer::Queued ? "queued" : result == AppendPacer::Coalesced ? "coalesced" : "full")
                   << ',' << messages[i].to << ',' << id_ << ",0," << b.size() << ','
                   << messages[i].term << ',' << messages[i].sequence << ',' << pacer_.size() << '\n';
      } else Send(messages[i].to, b);
    }
    if (c_.appendPaceMs) {
      AppendPacer::Item item;
      if (pacer_.pop(NowMs(), c_.appendPaceMs, item)) Send(item.message.to, item.body);
    }
    if (c_.stagedAgreement && id_ == c_.initiator &&
        raft_->state().count("gka-selection-1") && !selectionCommitted_) {
      selectionCommitted_ = true;
      Event("selection_observed", "gka-selection-1");
    }
    if (lastRole_ != raft_->role() || lastTerm_ != raft_->term()) {
      Event(raft_->role() == Role::Leader ? "leader" :
            (raft_->role() == Role::Candidate ? "candidate" : "follower"));
      lastRole_ = raft_->role(); lastTerm_ = raft_->term();
    }
    if (raft_->role() == Role::Leader && committed_) {
      // Self-addressed UDP may synchronously reenter Receive.
      std::set<uint32_t> replies; replies.swap(waiting_);
      for (std::set<uint32_t>::iterator i = replies.begin(); i != replies.end(); ++i)
        Send(*i, Client(3));
    }
  }
  void Receive(Ptr<Socket> socket) {
    Address address;
    while (Ptr<Packet> packet = socket->RecvFrom(address)) {
      ++rx_; rxBytes_ += packet->GetSize();
      const double draw = static_cast<double>(drop_()) / 4294967296.0;
      if (draw < c_.loss) { ++dropped_; continue; }
      if (!InetSocketAddress::IsMatchingType(address)) { ++rejected_; continue; }
      InetSocketAddress endpoint = InetSocketAddress::ConvertFrom(address);
      uint32_t source = c_.n;
      for (uint32_t i = 0; i < c_.n; ++i)
        if (endpoint.GetIpv4() == ips_.GetAddress(i)) source = i;
      if (source == c_.n || endpoint.GetPort() != 9000) { ++rejected_; continue; }
      Bytes bytes(packet->GetSize()), body;
      if (!bytes.empty()) packet->CopyData(&bytes[0], bytes.size());
      Reassembler::Result status = assembler_.accept(source, bytes, NowMs(), body);
      Transport("receive", source, bytes, static_cast<int>(status));
      if (status == Reassembler::Rejected) ++rejected_;
      if (status != Reassembler::Complete) continue;
      ++complete_;
      try {
        Reader r(body); const uint64_t kind = r.get(1);
        if (kind == 1) {
          Message m; Bytes wire(body.begin() + 1, body.end());
          if (!decode(wire, m) || m.from != source || m.to != id_) { ++rejected_; continue; }
          Reader fragmentReader(bytes); fragmentReader.get(12);
          const uint64_t transportId = fragmentReader.get(8);
          transport_ << NowNs() << ',' << id_ << ",reassembled_"
                     << (m.kind == Kind::Append ? "append" : m.kind == Kind::AppendReply ? "reply" : "vote")
                     << ',' << source << ',' << source << ',' << transportId << ','
                     << m.prev + m.entries.size() << ',' << m.term << ',' << m.sequence
                     << ',' << m.accepted << '\n';
          if (raft_) raft_->receive(m);
          else ++rejected_;
        } else if (kind == 2) {
          const std::string request = r.text(), value = r.text();
          const bool selectionRequest = c_.stagedAgreement && request == "gka-selection-1";
          if (!raft_) { ++rejected_; continue; }
          if (r.p != body.size() || source != c_.initiator ||
              (selectionRequest ? value.size() != (c_.cryptoAgreement ? 32U : 64U * c_.n) :
               request != "gka-single-1" ||
               (!c_.cryptoAgreement && value.size() != 208U * c_.n - 16) ||
               (c_.cryptoAgreement && (value.empty() || value.size() > 200000))) ||
              (c_.stagedAgreement && !selectionRequest &&
               !raft_->state().count("gka-selection-1"))) {
            ++rejected_; continue;
          }
          if (c_.cryptoAgreement) {
            if (selectionRequest) {
              const daagka::Bytes expected = daagka::transcript(session_, cryptoRoster_);
              if (value != std::string(expected.begin(), expected.end())) { ++rejected_; continue; }
            } else {
              const auto selected = raft_->state().find("gka-selection-1");
              const daagka::Bytes expected = daagka::transcript(session_, cryptoRoster_);
              if (selected == raft_->state().end() ||
                  selected->second != std::string(expected.begin(), expected.end())) {
                ++rejected_; continue;
              }
              const auto item = DecodeSelection(value);
              const daagka::Bytes t = daagka::transcript(session_, cryptoRoster_);
              if (item.leader != "uav-" + std::to_string(c_.initiator)) {
                ++rejected_; continue;
              }
              if (item.digest != daagka::selection_digest(t, item)) { ++rejected_; continue; }
              daagka::verify_selection_proof(t, item, daagka::lookup(cryptoRoster_, item.leader));
            }
          }
          if (raft_->role() == Role::Leader && receivedTerms_.insert(raft_->term()).second)
            Event("leader_first_receive", request);
          Event("client_request_received", request);
          if (raft_->propose(request, value)) { waiting_.insert(source); Event("proposal_accepted", request); }
          else Event("proposal_refused", request);
        } else if (kind == 3) {
          const std::string request = r.text();
          if (r.p != body.size() || request != "gka-single-1" || id_ != c_.initiator || !ready_) {
            ++rejected_; continue;
          }
          if (c_.stagedAgreement && !selectionCommitted_) continue;
          if (!c_.cryptoAgreement && !confirmed_) {
            confirmed_ = true; confirmMs_ = NowNs(); Event("client_confirm");
          }
        } else ++rejected_;
      } catch (const std::exception&) { ++rejected_; }
      Flush();
    }
  }
  void Tick() {
    assembler_.expire(NowMs());
    if (raft_) raft_->tick(NowMs());
    Flush();
    if (id_ == c_.initiator && raft_) {
      if (!read_ && NowMs() >= c_.start && raft_->knowsLeader()) {
        read_ = true; readMs_ = NowMs(); target_ = raft_->leader();
        Event("local_leader_ready"); Event("local_read");
        if (!c_.cryptoAgreement) localRead_ = materials_;
        Event("compute_start");
      }
      if (read_ && !ready_ && NowMs() - readMs_ >= c_.compute) {
        if (!c_.cryptoAgreement) result_.assign(208 * c_.n - 16, static_cast<char>(0xA5));
        if (c_.stagedAgreement) {
          if (c_.cryptoAgreement) {
            if (!cryptoMember_) throw std::runtime_error("crypto member not configured");
            const daagka::Bytes digest = daagka::transcript(session_, cryptoRoster_);
            selection_.assign(digest.begin(), digest.end());
          } else selection_.assign(64 * c_.n, static_cast<char>(0x53));
          Event("selection_ready", "gka-selection-1");
        }
        ready_ = true;
        Event(c_.cryptoAgreement ? "modeled_compute_delay_done" : "compute_done");
      }
      // Once started, never reset the clock or gate retries on leader readiness.
      if (ready_ && !confirmed_ && NowMs() >= nextRetry_) {
        if (c_.cryptoAgreement && selectionCommitted_) PrepareCryptoMaterial();
        if (raft_->knowsLeader()) target_ = raft_->leader();
        if (c_.stagedAgreement && selectionCommitted_ &&
            raft_->state().count("gka-single-1")) {
          Event("material_observed");
          if (c_.cryptoAgreement) {
            try {
              const auto item = DecodeSelection(raft_->state().at("gka-single-1"));
              const auto started = std::chrono::steady_clock::now();
              const daagka::Bytes key = daagka::receive(*cryptoMember_, session_, cryptoRoster_,
                  item, item.digest, selectionState_);
              cryptoRecoverUs_ = static_cast<uint64_t>(std::chrono::duration_cast<
                  std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count());
              if (!issued_ || key != issued_->key) throw std::runtime_error("group key mismatch");
              Event("crypto_key_verified");
              confirmed_ = true;
              confirmMs_ = NowNs();
              Event("client_confirm");
            } catch (const std::exception&) { ++rejected_; nextRetry_ = NowMs() + c_.retry; }
          } else {
            confirmed_ = true;
            confirmMs_ = NowNs();
            Event("client_confirm");
          }
        } else {
          ++attempts_;
          if (attempts_ == 1) { firstSendNs_ = NowNs(); Event("client_first_send"); }
          Event("client_request");
          Send(target_, Client(2)); target_ = (target_ + 1) % (c_.coreNodes ? c_.coreNodes : c_.n);
          nextRetry_ = NowMs() + c_.retry;
        }
      }
    }
    if (NowMs() + 1 < c_.duration) Simulator::Schedule(MilliSeconds(1), &Peer::Tick, this);
  }
  void Summary(std::ostream& s) const {
    s << id_ << ',' << tx_ << ',' << txBytes_ << ',' << rx_ << ',' << rxBytes_ << ','
      << dropped_ << ',' << rejected_ << ',' << complete_ << ',' << assembler_.expired()
      << ',' << sendErrors_ << ',' << (raft_ ? raft_->applicationCount() : 0) << ',' << attempts_ << '\n';
  }
  void Timing(std::ostream& s) const {
    s << "initial_ready=" << (read_ ? 1 : 0) << "\ninitial_wait_ms="
      << (read_ ? readMs_ - c_.start : c_.duration - c_.start)
      << "\ninitial_wait_censored=" << (read_ ? 0 : 1) << "\nlocal_read_ms=";
    if (read_) s << readMs_;
    s << "\nonline_latency_ms=";
    if (confirmed_) s << std::fixed << std::setprecision(6) << LatencyNs() / 1000000.0;
    s << "\nonline_latency_ns=";
    if (confirmed_) s << LatencyNs();
    s << "\nrequest_to_confirm_ns=";
    if (confirmed_) s << confirmMs_ - firstSendNs_;
    s << "\nstart_to_confirm_ns=";
    if (confirmed_) s << confirmMs_ - c_.start * 1000000;
    s << "\ncrypto_issue_cpu_us=";
    if (c_.cryptoAgreement && issued_) s << cryptoIssueUs_;
    s << "\ncrypto_recover_cpu_us=";
    if (c_.cryptoAgreement && confirmed_) s << cryptoRecoverUs_;
    s << '\n';
  }
  bool Confirmed() const { return confirmed_; }
  uint64_t LatencyNs() const { return confirmMs_ - readMs_ * 1000000; }
 private:
  AppendPacer pacer_;
  uint32_t id_; const Settings& c_; const Ipv4InterfaceContainer& ips_; std::ostream& events_;
  std::ostream& transport_;
  std::mt19937 election_, drop_; uint64_t serial_; Role lastRole_; Term lastTerm_;
  bool committed_, read_, ready_, confirmed_;
  bool selectionCommitted_ = false;
  daagka::Bytes session_, committedSelectionDigest_;
  daagka::SelectionState selectionState_;
  std::unique_ptr<daagka::Member> cryptoMember_;
  std::vector<daagka::PublicMember> cryptoRoster_;
  std::unique_ptr<daagka::Issued> issued_;
  uint64_t readMs_, nextRetry_; uint32_t target_;
  uint64_t confirmMs_, attempts_, tx_, txBytes_, rx_, rxBytes_, dropped_, rejected_, complete_, sendErrors_;
  std::unique_ptr<Raft> raft_; Ptr<Socket> socket_; Reassembler assembler_;
  std::vector<std::string> materials_, localRead_;
  uint64_t firstSendNs_ = 0, cryptoIssueUs_ = 0, cryptoRecoverUs_ = 0;
  std::set<Term> receivedTerms_;
  std::set<std::pair<uint32_t, std::pair<uint64_t, uint64_t> > > appendSends_;
  std::string result_, selection_; std::set<uint32_t> waiting_;
};
#endif
