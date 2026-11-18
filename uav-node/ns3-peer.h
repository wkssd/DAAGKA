#ifndef IOT_NS3_PEER_H
#define IOT_NS3_PEER_H
#include "wire.h"
#include "append-pacer.h"
#include "crypto.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include <memory>
#include <random>
#include <deque>
#include <limits>

using namespace ns3;
using namespace iotraft;
using namespace iotraft::wire;
struct Settings {
  uint32_t n=3, initiator=0, seed=17, rngRun=1, rounds=1;
  uint32_t selectionBytes=0, materialBytes=0;
  bool olsr=true, staticMobility=false, presetArp=false;
  uint64_t electionBase=600, appendRetryMs=0, appendRetryMaxMs=1600, appendPaceMs=0;
  uint64_t prepareMs=0, deriveMs=0, duration=60000, start=100, retry=200, gmStepMs=500, arpDeadMs=1000;
  double loss=0, distance=400, height=100, speedMin=0, speedMax=20, alpha=0.85;
  std::string out;
  void Resolve() {
    if (n<3 || n>50 || initiator>=n || !rounds || uint64_t(n)*rounds>10000 || !retry || !seed || !rngRun || !arpDeadMs || arpDeadMs>3600000 ||
        !duration || duration>3600000 || start>=duration || prepareMs>duration || deriveMs>duration ||
        electionBase<=100 || electionBase>60000 || appendPaceMs>1000 ||
        (appendPaceMs && !appendRetryMs) || appendRetryMaxMs>60000 ||
        (appendRetryMs && (appendRetryMs<100 || appendRetryMaxMs<appendRetryMs)) ||
        !std::isfinite(loss) || loss<0 || loss>1)
      throw std::invalid_argument("invalid node/protocol parameters");
    const uint32_t selection=static_cast<uint32_t>(gka::SelectionSize(n));
    const uint32_t material=static_cast<uint32_t>(gka::MaterialSize(n));
    if ((selectionBytes && selectionBytes!=selection) || (materialBytes && materialBytes!=material))
      throw std::invalid_argument("payload size must match the real GKA encoding");
    selectionBytes=selection; materialBytes=material;
    const size_t digits=std::to_string(rounds).size();
    if (!fitsEntry(14+digits,selectionBytes) || !fitsEntry(13+digits,materialBytes))
      throw std::invalid_argument("payload exceeds a single Raft entry budget");
  }
};
// Each private-key vector is moved to its owner and only public rosters are shared.
struct GkaSetup {
  std::shared_ptr<const std::vector<std::string> > selections;
  std::vector<std::vector<gka::KeyPair> > privateKeys;
  explicit GkaSetup(const Settings& c) {
    if(c.n<3 || c.n>50 || !c.rounds || uint64_t(c.n)*c.rounds>10000)
      throw std::invalid_argument("invalid GKA setup budget");
    for(uint32_t node=0;node<c.n;++node) {
      std::string seed=gka::RandomSeed();
      privateKeys.push_back(gka::DeriveKeys(seed,c.rounds));gka::Erase(seed);
    }
    std::shared_ptr<std::vector<std::string> > rosters(new std::vector<std::string>);
    for(uint32_t round=0;round<c.rounds;++round) {
      std::vector<std::string> publicKeys;
      for(uint32_t node=0;node<c.n;++node) publicKeys.push_back(privateKeys[node][round].publicKey);
      rosters->push_back(gka::Selection(publicKeys));
    }
    selections=rosters;
  }
};
static uint64_t NowMs() { return Simulator::Now().GetMilliSeconds(); }
static uint64_t NowNs() { return Simulator::Now().GetNanoSeconds(); }
static std::mt19937 Seeded(const Settings& c,uint32_t id,uint32_t domain) {
  std::seed_seq seed{c.seed,c.rngRun,id,domain}; return std::mt19937(seed);
}
class Peer {
 public:
  Peer(uint32_t id,const Settings& c,const Ipv4InterfaceContainer& ips,Ptr<Node> node,
       std::shared_ptr<const std::vector<std::string> > selections,std::vector<gka::KeyPair> privateKeys)
    : id_(id),c_(c),ips_(ips),
      election_(Seeded(c,id,1)),drop_(Seeded(c,id,2)),
      selections_(std::move(selections)),privateKeys_(std::move(privateKeys)) {
    if (id>=c.n || !c.selectionBytes || !c.materialBytes) throw std::invalid_argument("unresolved settings");
    if(!selections_ || selections_->size()!=c.rounds || privateKeys_.size()!=c.rounds)
      throw std::invalid_argument("missing preconfigured GKA keys");
    for(uint32_t round=0;round<c.rounds;++round)
      if(selections_->at(round).size()!=c.selectionBytes || privateKeys_[round].secret.size()!=32 ||
         privateKeys_[round].publicKey!=selections_->at(round).substr(64*id,64))
        throw std::invalid_argument("GKA key does not match node roster slot");
    std::vector<NodeId> members; for(uint32_t i=0;i<c.n;++i) members.push_back(i);
    raft_.reset(new Raft(id,members,c.electionBase,100,
      [this](NodeId,Term,uint64_t base){return base+election_()%base;}));
    raft_->setRetryPolicy(c.appendRetryMs,c.appendRetryMaxMs);
    raft_->setObserver([this](bool applied,bool,Index index,const Entry& entry){
      if(applied) applied_.push_back(std::make_pair(index,entry));
    });
    socket_=Socket::CreateSocket(node,UdpSocketFactory::GetTypeId());
    if(socket_->Bind(InetSocketAddress(Ipv4Address::GetAny(),9000))!=0)
      throw std::runtime_error("UDP bind failed");
    socket_->SetRecvCallback(MakeCallback(&Peer::Receive,this));
  }
  ~Peer() { for(auto& item:rounds_) gka::Erase(item.second.pendingKey); }
  std::string GroupKeyDigest(uint64_t round) const {
    auto i=rounds_.find(round);return i!=rounds_.end() && i->second.complete?i->second.keyDigest:"";
  }
  bool StartRound(uint64_t round) {
    raft_->tick(NowMs()); AfterCore();
    if(id_!=c_.initiator || !round || round>c_.rounds) return false;
    auto found=rounds_.find(round);
    if(found!=rounds_.end() && found->second.started) return true;
    if(activeRound_ && !rounds_.at(activeRound_).complete) return false;
    RoundState& r=rounds_[round]; r.started=true; r.selectionValue=selections_->at(round-1);
    activeRound_=round;
    const auto appliedSelection=raft_->state().find(Request(round,false));
    if(appliedSelection!=raft_->state().end() && appliedSelection->second!=r.selectionValue)
      Reject(round,true);
    AfterCore(); return true;
  }
  bool RoundComplete(uint64_t round) const {
    auto i=rounds_.find(round); return i!=rounds_.end() && i->second.complete;
  }
  uint64_t CompletedRounds() const {
    uint64_t count=0; for(const auto& r:rounds_) count+=r.second.complete; return count;
  }
  void SetRoundCompleteCallback(std::function<void(NodeId,uint64_t)> callback) { completeCallback_=callback; }
  void Tick() {
    assembler_.expire(NowMs()); Wake();
    if(NowMs()+1<c_.duration) Simulator::Schedule(MilliSeconds(1),&Peer::Tick,this);
  }
 private:
  friend struct PeerProbe;
  struct RoundState {
    bool started=false,selection=false,material=false,prepared=false,complete=false,failed=false;
    uint64_t prepareDue=0,deriveDue=0,nextRetry=0;
    std::string selectionValue,materialValue,pendingKey,keyDigest;
  };
  bool ParseRequest(const std::string& request,uint64_t& round,bool& material) const {
    if(request.compare(0,4,"gka/")!=0) return false;
    const size_t end=request.find('/',4);
    if(end==std::string::npos || end==4 || request[4]=='0') return false;
    round=0;
    for(size_t i=4;i<end;++i) {
      if(request[i]<'0' || request[i]>'9' || round>(std::numeric_limits<uint64_t>::max()-9)/10) return false;
      round=round*10+static_cast<unsigned>(request[i]-'0');
    }
    if(!round || round>c_.rounds) return false;
    const std::string phase=request.substr(end+1);
    material=phase=="material"; return material || phase=="selection";
  }
  static std::string Request(uint64_t round,bool material) {
    return "gka/"+std::to_string(round)+(material?"/material":"/selection");
  }
  void Reject(uint64_t round,bool local) {
    if(local && rounds_.count(round)) {
      rounds_.at(round).failed=true;gka::Erase(rounds_.at(round).pendingKey);
      gka::Erase(privateKeys_.at(round-1).secret);
    }
  }
  void HandleSubmit(NodeId from,const std::string& request,const std::string& value) {
    uint64_t round=0; bool material=false;
    if(from!=c_.initiator || !ParseRequest(request,round,material) ||
       value.size()!=(material?c_.materialBytes:c_.selectionBytes) || !fitsEntry(request.size(),value.size())) {
      Reject(round,from==id_); return;
    }
    if(raft_->role()!=Role::Leader) return;
    for(const Entry& e:raft_->log()) if(e.request==request && e.value!=value) {
      Reject(round,from==id_); return;
    }
    if(material && !raft_->state().count(Request(round,false))) return;
    if((!material && value!=selections_->at(round-1)) ||
       (material && !gka::ValidateMaterial(value,raft_->state().at(Request(round,false)),c_.initiator))) {
      Reject(round,from==id_);return;
    }
    if(!raft_->propose(request,value)) Reject(round,from==id_);
  }
  void ProcessApplied() {
    while(!applied_.empty()) {
      const Entry entry=applied_.front().second; applied_.pop_front();
      uint64_t round=0; bool material=false;
      if(!ParseRequest(entry.request,round,material) ||
         entry.value.size()!=(material?c_.materialBytes:c_.selectionBytes) ||
         raft_->state().at(entry.request)!=entry.value)
        throw std::runtime_error("invalid or conflicting applied business record");
      RoundState& r=rounds_[round];
      if(id_==c_.initiator && r.started &&
         entry.value!=(material?r.materialValue:r.selectionValue)) {
        Reject(round,true); continue;
      }
      if(r.failed) continue;
      if(!material && !r.selection) {
        if(entry.value!=selections_->at(round-1)) {
          Reject(round,true);continue;
        }
        r.selectionValue=entry.value;
        r.selection=true; r.prepareDue=NowNs()+c_.prepareMs*1000000; r.nextRetry=0;
        if(id_==c_.initiator) Simulator::Schedule(MilliSeconds(c_.prepareMs),&Peer::Wake,this);
      } else if(material && !r.material) {
        if(!r.selection) throw std::runtime_error("material applied before selection");
        if(!gka::ValidateMaterial(entry.value,r.selectionValue,c_.initiator)) {
          Reject(round,true);continue;
        }
        r.materialValue=entry.value;
        r.material=true; r.deriveDue=NowNs()+c_.deriveMs*1000000;
        Simulator::Schedule(MilliSeconds(c_.deriveMs),&Peer::Wake,this);
      }
    }
  }
  void DriveRounds() {
    for(auto& item:rounds_) {
      const uint64_t round=item.first; RoundState& r=item.second;
      if(r.failed) continue;
      if(r.material && !r.complete && NowNs()>=r.deriveDue) {
        try {
          std::string key;
          if(id_==c_.initiator) {
            if(!r.prepared || r.pendingKey.size()!=32) throw std::runtime_error("missing initiator key");
            key.swap(r.pendingKey);
          } else key=gka::Derive(id_,c_.initiator,privateKeys_.at(round-1),r.selectionValue,r.materialValue);
          r.keyDigest=gka::Digest(key);gka::Erase(key);gka::Erase(privateKeys_.at(round-1).secret);
          r.complete=true; completed_.push_back(round);
        } catch(const std::exception&) {
          gka::Erase(r.pendingKey);Reject(round,true);
        }
      }
      if(id_!=c_.initiator || !r.started || r.material || r.complete) continue;
      if(r.selection && !r.prepared) {
        if(NowNs()<r.prepareDue) continue;
        try {
          gka::Issued issued=gka::Issue(c_.initiator,privateKeys_.at(round-1),r.selectionValue);
          r.materialValue.swap(issued.material);r.pendingKey.swap(issued.key);r.prepared=true;
        } catch(const std::exception&) {
          Reject(round,true);continue;
        }
      }
      if(NowMs()<r.nextRetry) continue;
      const bool material=r.selection;
      const std::string request=Request(round,material);
      const std::string& value=material?r.materialValue:r.selectionValue;
      NodeId target=raft_->knowsLeader()?raft_->leader():nextTarget_;
      nextTarget_=(target+1)%c_.n;
      r.nextRetry=NowMs()+c_.retry;
      if(target==id_) HandleSubmit(id_,request,value);
      else Send(target,encodeClientSubmit(request,value));
    }
  }
  void AfterCore() {
    if(processing_) throw std::logic_error("reentrant node processing");
    processing_=true;
    do { ProcessApplied(); Flush(); DriveRounds(); } while(!applied_.empty());
    // A local proposal can enqueue RPCs without applying yet.
    Flush(); processing_=false;
    std::vector<uint64_t> completed; completed.swap(completed_);
    for(uint64_t round:completed) if(completeCallback_) completeCallback_(id_,round);
  }
  void Wake() { raft_->tick(NowMs()); AfterCore(); }
  void Flush() {
    if(c_.appendPaceMs) pacer_.prune([this](const Message& m){return raft_->isPending(m);});
    for(const Message& m:raft_->drain()) {
      Bytes body=encode(m); body.insert(body.begin(),1);
      bool business=false; for(const Entry& e:m.entries) business|=!e.request.empty();
      if(c_.appendPaceMs && m.kind==Kind::Append && business) {
        if(raft_->isPending(m)) pacer_.enqueue(m,body);
      } else Send(m.to,body);
    }
    if(c_.appendPaceMs) {
      AppendPacer::Item item;
      if(pacer_.pop(NowMs(),c_.appendPaceMs,item)) Send(item.message.to,item.body);
    }
  }
  void Send(NodeId to,const Bytes& body) {
    if(to==id_ || to>=c_.n || body.empty()) throw std::logic_error("invalid remote destination/body");
    if(serial_==std::numeric_limits<uint64_t>::max()) throw std::overflow_error("transport serial exhausted");
    if(body[0]==1) {
      Message m;
      if(!decode(Bytes(body.begin()+1,body.end()),m) || m.to!=to)
        throw std::logic_error("bad outgoing RPC");
    }
    const std::vector<Bytes> parts=fragment(body,id_,++serial_);
    for(size_t i=0;i<parts.size();++i) {
      Ptr<Packet> packet=Create<Packet>(parts[i].data(),parts[i].size());
      socket_->SendTo(packet,0,InetSocketAddress(ips_.GetAddress(to),9000));
    }
  }
  void OnPacket(const Address& address,Ptr<Packet> packet) {
    if(static_cast<double>(drop_())/4294967296.0<c_.loss) return;
    if(!InetSocketAddress::IsMatchingType(address)) return;
    const InetSocketAddress endpoint=InetSocketAddress::ConvertFrom(address);
    NodeId source=c_.n;
    for(NodeId i=0;i<c_.n;++i) if(endpoint.GetIpv4()==ips_.GetAddress(i)) source=i;
    if(source==c_.n || endpoint.GetPort()!=9000) return;
    Bytes bytes(packet->GetSize()),body;
    if(!bytes.empty()) packet->CopyData(bytes.data(),bytes.size());
    if(assembler_.accept(source,bytes,NowMs(),body)!=Reassembler::Complete || body.empty()) return;
    if(body[0]==1) {
      Message m;
      if(!decode(Bytes(body.begin()+1,body.end()),m) || m.from!=source || m.to!=id_) return;
      raft_->receive(m);
    } else if(body[0]==2) {
      std::string request,value;
      if(!decodeClientSubmit(body,request,value)) return;
      HandleSubmit(source,request,value);
    }
  }
  void Receive(Ptr<Socket> socket) {
    Address address;
    while(Ptr<Packet> packet=socket->RecvFrom(address)) {
      raft_->tick(NowMs()); AfterCore();
      OnPacket(address,packet); AfterCore();
    }
  }
  NodeId id_; const Settings& c_; const Ipv4InterfaceContainer& ips_;
  std::mt19937 election_,drop_;
  std::shared_ptr<const std::vector<std::string> > selections_;
  std::vector<gka::KeyPair> privateKeys_;
  std::unique_ptr<Raft> raft_; Ptr<Socket> socket_; Reassembler assembler_; AppendPacer pacer_;
  std::map<uint64_t,RoundState> rounds_; std::deque<std::pair<Index,Entry> > applied_;
  std::vector<uint64_t> completed_;
  std::function<void(NodeId,uint64_t)> completeCallback_;
  bool processing_=false;
  uint64_t activeRound_=0,serial_=0; NodeId nextTarget_=0;
};
#endif
