#ifndef IOT_RAFT_CORE_H
#define IOT_RAFT_CORE_H

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace iotraft {

typedef uint64_t Term;
typedef uint64_t Index;
typedef uint32_t NodeId;

enum class Role { Follower, Candidate, Leader };
enum class Kind { Vote, VoteReply, Append, AppendReply };

struct Entry {
  Term term;
  std::string request;
  std::string value;
  Entry(Term t = 0, const std::string& r = "", const std::string& v = "")
      : term(t), request(r), value(v) {}
};

struct Message {
  Kind kind;
  NodeId from, to;
  Term term, lastTerm;
  Index prev, commit, matched;
  uint64_t sequence;
  bool accepted;
  std::vector<Entry> entries;
  Message() : kind(Kind::Vote), from(0), to(0), term(0), lastTerm(0),
              prev(0), commit(0), matched(0), sequence(0), accepted(false) {}
};

// Volatile, fixed-membership protocol core. Transport owns delivery and time.
class Raft {
 public:
  typedef std::function<uint64_t(NodeId, Term, uint64_t)> ElectionTimeout;
  // Called synchronously at the transition; transport supplies its own clock.
  typedef std::function<void(bool, bool, Index, const Entry&)> Observer;
  void setObserver(Observer observer) { observer_ = observer; }

  // Zero retains the legacy heartbeat-paced retransmission policy.
  void setRetryPolicy(uint64_t initialMs, uint64_t maximumMs) {
    if (role_ != Role::Follower || term_ != 0 ||
        (initialMs && (initialMs < heartbeatMs_ || maximumMs < initialMs)))
      throw std::invalid_argument("invalid retry policy or already started");
    retryInitial_ = initialMs; retryMaximum_ = maximumMs;
  }
  typedef std::function<void(const Message&, const char*)> RpcObserver;
  void setRpcObserver(RpcObserver observer) { rpcObserver_ = observer; }

  Raft(NodeId id, const std::vector<NodeId>& members,
       uint64_t electionMs, uint64_t heartbeatMs = 30,
       ElectionTimeout timeout = ElectionTimeout())
      : id_(id), members_(members.begin(), members.end()), role_(Role::Follower),
        term_(0), voted_(false), voteFor_(0), leaderKnown_(false), leader_(0),
        commit_(0), applied_(0), now_(0), electionMs_(electionMs),
        heartbeatMs_(heartbeatMs), electionDeadline_(electionMs), heartbeatDeadline_(0),
        sequence_(0), timeout_(timeout) {
    if (members_.size() != members.size() || members_.empty() ||
        members_.size() > 50 || !members_.count(id) || !heartbeatMs ||
        electionMs <= heartbeatMs)
      throw std::invalid_argument("invalid membership or timeouts");
    log_.push_back(Entry());
    resetElection();
  }

  Role role() const { return role_; }
  NodeId id() const { return id_; }
  Term term() const { return term_; }
  Index committed() const { return commit_; }
  Index applied() const { return applied_; }
  Index lastIndex() const { return log_.size() - 1; }
  const std::vector<Entry>& log() const { return log_; }
  const std::map<std::string, std::string>& state() const { return state_; }
  size_t applicationCount() const { return state_.size(); }
  bool knowsLeader() const { return leaderKnown_; }
  NodeId leader() const { return leader_; }
  bool isPending(const Message& message) const {
    const auto found = pending_.find(message.to);
    return role_ == Role::Leader && message.term == term_ &&
        message.from == id_ && found != pending_.end() &&
        found->second.sequence == message.sequence;
  }

  std::vector<Message> drain() {
    std::vector<Message> result;
    result.swap(outbox_);
    return result;
  }

  void tick(uint64_t now) {
    if (now < now_) throw std::invalid_argument("clock must be monotonic");
    now_ = now;
    if (role_ == Role::Leader) {
      if (now >= heartbeatDeadline_) broadcast();
      else if (retryInitial_) {
        for (std::map<NodeId, uint64_t>::const_iterator i = retryDue_.begin();
             i != retryDue_.end(); ++i)
          if (now >= i->second) sendAppend(i->first);
      }
    } else if (now >= electionDeadline_) {
      elect();
    }
  }

  // A stable request ID is mandatory across client retries and leader changes.
  bool propose(const std::string& request, const std::string& value) {
    if (role_ != Role::Leader || request.empty()) return false;
    for (Index i = 1; i <= lastIndex(); ++i) {
      if (log_[i].request == request) return log_[i].value == value;
    }
    log_.push_back(Entry(term_, request, value));
    advanceCommit();
    broadcast();
    return true;
  }

  void receive(const Message& m) {
    if (m.to != id_ || m.from == id_ || !members_.count(m.from)) return;
    if (m.term > term_) follow(m.term);
    if (m.term < term_) {
      if (m.kind == Kind::Vote || m.kind == Kind::Append) {
        Message reply = make(m.kind == Kind::Vote ? Kind::VoteReply : Kind::AppendReply, m.from);
        reply.sequence = m.sequence;
        outbox_.push_back(reply);
      }
      return;
    }
    if (m.kind == Kind::Vote) {
      Message reply = make(Kind::VoteReply, m.from);
      const bool fresh = m.lastTerm > log_.back().term ||
          (m.lastTerm == log_.back().term && m.prev >= lastIndex());
      if (fresh && (!voted_ || voteFor_ == m.from)) {
        voted_ = true;
        voteFor_ = m.from;
        reply.accepted = true;
        resetElection();
      }
      outbox_.push_back(reply);
    } else if (m.kind == Kind::VoteReply) {
      if (role_ == Role::Candidate && m.accepted) {
        votes_.insert(m.from);
        if (votes_.size() >= quorum()) lead();
      }
    } else if (m.kind == Kind::Append) {
      append(m);
    } else if (m.kind == Kind::AppendReply && role_ == Role::Leader) {
      std::map<NodeId, Message>::iterator pending = pending_.find(m.from);
      if (pending == pending_.end() || m.sequence != pending->second.sequence) {
        if (rpcObserver_) rpcObserver_(m, "unmatched");
        return;
      }
      const Index end = pending->second.prev + pending->second.entries.size();
      if (m.accepted && m.matched != end) {
        if (rpcObserver_) rpcObserver_(m, "wrong_end");
        return;
      }
      if (rpcObserver_) rpcObserver_(m, m.accepted ? "matched_success" : "matched_failure");
      pending_.erase(pending);
      retryDue_.erase(m.from); retryDelay_.erase(m.from);
      if (m.accepted) {
        match_[m.from] = std::max(match_[m.from], m.matched);
        next_[m.from] = match_[m.from] + 1;
        advanceCommit();
        if (next_[m.from] <= lastIndex()) sendAppend(m.from);
      } else {
        next_[m.from] = std::max(match_[m.from] + 1,
                               next_[m.from] > 1 ? next_[m.from] - 1 : Index(1));
        sendAppend(m.from);
      }
    }
  }

 private:
  size_t quorum() const { return members_.size() / 2 + 1; }
  void resetElection() {
    const uint64_t delay = timeout_ ? timeout_(id_, term_, electionMs_) : electionMs_;
    if (delay <= heartbeatMs_ || delay > std::numeric_limits<uint64_t>::max() - now_)
      throw std::invalid_argument("invalid election timeout sample");
    electionDeadline_ = now_ + delay;
  }
  Message make(Kind kind, NodeId to) const {
    Message m;
    m.kind = kind; m.from = id_; m.to = to; m.term = term_;
    return m;
  }
  void follow(Term term) {
    role_ = Role::Follower;
    if (term > term_) { term_ = term; voted_ = false; }
    leaderKnown_ = false;
    votes_.clear();
    pending_.clear(); retryDue_.clear(); retryDelay_.clear();
    resetElection();
  }
  void elect() {
    ++term_;
    role_ = Role::Candidate;
    voted_ = true;
    voteFor_ = id_;
    leaderKnown_ = false;
    votes_.clear(); votes_.insert(id_);
    resetElection();
    if (votes_.size() >= quorum()) { lead(); return; }
    for (std::set<NodeId>::const_iterator i = members_.begin(); i != members_.end(); ++i) {
      if (*i == id_) continue;
      Message m = make(Kind::Vote, *i);
      m.prev = lastIndex(); m.lastTerm = log_.back().term;
      outbox_.push_back(m);
    }
  }
  void lead() {
    role_ = Role::Leader; leaderKnown_ = true; leader_ = id_;
    next_.clear(); match_.clear(); pending_.clear(); retryDue_.clear(); retryDelay_.clear();
    for (std::set<NodeId>::const_iterator i = members_.begin(); i != members_.end(); ++i) {
      next_[*i] = lastIndex() + 1; match_[*i] = 0;
    }
    // A current-term no-op allows safe commitment of preceding terms.
    log_.push_back(Entry(term_));
    advanceCommit();
    broadcast();
  }
  void sendAppend(NodeId peer) {
    if (pending_.count(peer)) {
      if (!retryInitial_ || now_ >= retryDue_.at(peer)) {
        outbox_.push_back(pending_.at(peer));
        if (retryInitial_) {
          uint64_t& delay = retryDelay_[peer];
          delay = delay >= retryMaximum_ - delay ? retryMaximum_ : delay * 2;
          retryDue_[peer] = now_ + delay;
        }
      }
      return;
    }
    Message m = make(Kind::Append, peer);
    m.prev = next_[peer] - 1;
    m.lastTerm = log_[m.prev].term;
    m.commit = commit_;
    m.sequence = ++sequence_;
    const Index end = std::min(lastIndex(), m.prev + 16);
    for (Index i = m.prev + 1; i <= end; ++i) m.entries.push_back(log_[i]);
    pending_[peer] = m;
    if (retryInitial_) {
      retryDelay_[peer] = retryInitial_;
      retryDue_[peer] = now_ + retryInitial_;
    }
    outbox_.push_back(m);
  }
  void broadcast() {
    heartbeatDeadline_ = now_ + heartbeatMs_;
    for (std::set<NodeId>::const_iterator i = members_.begin(); i != members_.end(); ++i) {
      if (*i == id_) continue;
      if (retryInitial_ && pending_.count(*i)) {
        // The heartbeat proves only an already acknowledged prefix. Its fresh
        // sequence is never entered in pending_, so its reply cannot commit data.
        Message heartbeat = make(Kind::Append, *i);
        heartbeat.prev = match_[*i]; heartbeat.lastTerm = log_[heartbeat.prev].term;
        heartbeat.commit = commit_; heartbeat.sequence = ++sequence_;
        outbox_.push_back(heartbeat);
      }
      sendAppend(*i);
    }
  }
  void append(const Message& m) {
    if (role_ != Role::Follower) follow(term_);
    leader_ = m.from; leaderKnown_ = true;
    resetElection();
    Message reply = make(Kind::AppendReply, m.from);
    reply.sequence = m.sequence;
    if (m.prev > lastIndex() || log_[m.prev].term != m.lastTerm) {
      outbox_.push_back(reply); return;
    }
    Index at = m.prev + 1;
    for (size_t j = 0; j < m.entries.size(); ++j, ++at) {
      if (m.entries[j].term > m.term || !m.entries[j].term) {
        outbox_.push_back(reply); return;
      }
      if (at <= lastIndex() && log_[at].term != m.entries[j].term) {
        if (at <= commit_) { outbox_.push_back(reply); return; }
        log_.resize(at);
      }
      if (at > lastIndex()) log_.push_back(m.entries[j]);
    }
    reply.accepted = true;
    reply.matched = m.prev + m.entries.size();
    if (m.commit > commit_) {
      setCommit(std::max(commit_, std::min(m.commit, reply.matched)), false);
    }
    outbox_.push_back(reply);
  }
  void advanceCommit() {
    for (Index n = lastIndex(); n > commit_; --n) {
      if (log_[n].term != term_) continue;
      size_t count = 1;
      for (std::set<NodeId>::const_iterator i = members_.begin(); i != members_.end(); ++i)
        if (*i != id_ && match_[*i] >= n) ++count;
      if (count >= quorum()) { setCommit(n, true); break; }
    }
  }
  void setCommit(Index next, bool majority) {
    const Index previous = commit_;
    commit_ = next;
    if (observer_)
      for (Index i = previous + 1; i <= commit_; ++i)
        observer_(false, majority, i, log_[i]);
    apply();
  }
  void apply() {
    while (applied_ < commit_) {
      const Entry& e = log_[++applied_];
      if (!e.request.empty()) {
        state_.insert(std::make_pair(e.request, e.value));
        if (observer_) observer_(true, false, applied_, e);
      }
    }
  }

  NodeId id_;
  std::set<NodeId> members_;
  Role role_;
  Term term_;
  bool voted_;
  NodeId voteFor_;
  bool leaderKnown_;
  NodeId leader_;
  Index commit_, applied_;
  uint64_t now_, electionMs_, heartbeatMs_, electionDeadline_, heartbeatDeadline_, sequence_;
  ElectionTimeout timeout_;
  Observer observer_;
  RpcObserver rpcObserver_;
  uint64_t retryInitial_ = 0, retryMaximum_ = 0;
  std::map<NodeId, uint64_t> retryDue_, retryDelay_;
  std::set<NodeId> votes_;
  std::vector<Entry> log_;
  std::vector<Message> outbox_;
  std::map<NodeId, Index> next_, match_;
  std::map<NodeId, Message> pending_;
  std::map<std::string, std::string> state_;
};

}  // namespace iotraft
#endif
