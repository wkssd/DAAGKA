#include "ns3-peer.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-module.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#include <cmath>

static void DropTrace(std::ostream* out, uint32_t node, std::string layer, Ptr<const Packet> packet) {
  *out << NowNs() << ',' << node << ',' << layer << ',' << packet->GetUid() << ',' << packet->GetSize() << '\n';
}

static void CheckSegment(double edge, double height, double step, Ptr<const MobilityModel> model) {
  const Vector p = model->GetPosition(), v = model->GetVelocity();
  const Vector end(p.x + v.x * step, p.y + v.y * step, p.z + v.z * step);
  if (p.x < -1e-8 || p.x > edge + 1e-8 || p.y < -1e-8 || p.y > edge + 1e-8 ||
      p.z < -1e-8 || p.z > height + 1e-8 || end.x < -1e-8 || end.x > edge + 1e-8 ||
      end.y < -1e-8 || end.y > edge + 1e-8 || end.z < -1e-8 || end.z > height + 1e-8)
    throw std::runtime_error("actual GM segment outside configured bounds");
}

static void Track(NodeContainer nodes, std::ostream* out, uint64_t duration) {
  for (uint32_t i = 0; i < nodes.GetN(); ++i) {
    Ptr<MobilityModel> model = nodes.Get(i)->GetObject<MobilityModel>();
    Vector p = model->GetPosition(), v = model->GetVelocity();
    *out << NowMs() << ',' << i << ',' << p.x << ',' << p.y << ',' << p.z
         << ',' << v.x << ',' << v.y << ',' << v.z << ',' << NowNs() << '\n';
  }
  if (NowMs() + 100 <= duration)
    Simulator::Schedule(MilliSeconds(100), &Track, nodes, out, duration);
}

int main(int argc, char** argv) {
  try {
    Settings c; CommandLine cmd;
    double height = 0;
    cmd.AddValue("n", "Group participants 3..50", c.n);
    cmd.AddValue("coreNodes", "Raft voters 3..n; 0 retains legacy all-voter mode", c.coreNodes);
    cmd.AddValue("stagedAgreement", "Selection commit before material proposal", c.stagedAgreement);
    cmd.AddValue("cryptoAgreement", "Use P-256/AES-GCM prototype after selection commit", c.cryptoAgreement);
    cmd.AddValue("olsr", "Enable OLSR routing on all UAV nodes", c.olsr);
    cmd.AddValue("initiator", "Client member index, need not be leader", c.initiator);
    cmd.AddValue("seed", "Reproducible RNG seed", c.seed);
    cmd.AddValue("rngRun", "Run number for all RNG domains", c.rngRun);
    cmd.AddValue("staticMobility", "Constant-position control (default false)", c.staticMobility);
    cmd.AddValue("p", "Drop probability per received UDP datagram", c.loss);
    cmd.AddValue("presetArp", "Explicit resolved fixed-member IP/MAC cache control", c.presetArp);
    cmd.AddValue("electionBaseMs", "Election uniform integer window [base,2*base-1], heartbeat remains 100ms", c.electionBase);
    cmd.AddValue("appendRetryMs", "0=legacy; otherwise independent RPC initial retry interval", c.appendRetryMs);
    cmd.AddValue("appendRetryMaxMs", "Capped exponential RPC retry interval", c.appendRetryMaxMs);
    cmd.AddValue("appendPaceMs", "0=legacy send; bounded FIFO business RPC release interval", c.appendPaceMs);
    cmd.AddValue("computeMs", "Local modeled GKA compute delay", c.compute);
    cmd.AddValue("durationMs", "Simulation deadline; timeout means unknown", c.duration);
    cmd.AddValue("startMs", "Earliest readiness wait start, not online timing origin", c.start);
    cmd.AddValue("retryMs", "Retry locally known leader; otherwise rotate membership", c.retry);
    cmd.AddValue("distance", "Random initial horizontal box edge and X/Y bounds (m)", c.distance);
    cmd.AddValue("height", "Z extent and bound in meters; 0 repeats distance", height);
    cmd.AddValue("speed", "Gauss-Markov mean speed (m/s)", c.speed);
    cmd.AddValue("alpha", "Gauss-Markov memory, in [0,1)", c.alpha);
    cmd.AddValue("gmStepMs", "Gauss-Markov update interval", c.gmStepMs);
    cmd.AddValue("out", "New result directory; existing path refused", c.out);
    cmd.Parse(argc, argv);
    if (c.n < 3 || c.n > 50 || (c.cryptoAgreement && (!c.stagedAgreement || !c.coreNodes)) ||
        (c.coreNodes && (c.coreNodes < 3 || c.coreNodes > c.n || c.initiator >= c.coreNodes)) ||
        c.initiator >= c.n || !c.seed || !std::isfinite(c.loss) ||
        c.loss < 0 || c.loss > 1 || !c.retry || c.duration > 3600000 ||
        c.electionBase <= 100 || c.electionBase > 60000 ||
        c.appendPaceMs > 1000 || (c.appendPaceMs && !c.appendRetryMs) ||
        c.appendRetryMaxMs > 60000 || (c.appendRetryMs &&
          (c.appendRetryMs < 100 || c.appendRetryMaxMs < c.appendRetryMs)) ||
        c.start >= c.duration || c.compute > c.duration - c.start || c.out.empty() ||
        !std::isfinite(c.distance) || c.distance <= 0 || c.distance > 100000 ||
        !std::isfinite(c.speed) || c.speed < 0 || c.speed > 100 ||
        !std::isfinite(c.alpha) || c.alpha < 0 || c.alpha >= 1 ||
        !c.gmStepMs || c.gmStepMs > 60000 ||
        !std::isfinite(height) || height < 0 || height > 100000)
      throw std::invalid_argument("invalid parameters or missing --out");
    const double zMax = height > 0 ? height : c.distance;
    const double maxRange = std::sqrt(2.0 * c.distance * c.distance + zMax * zMax);
    // NS3.25 reverses once per step: <= half the box edge guarantees the
    // reversed endpoint is inside too. No output or mobility clipping is used.
    if (!c.rngRun || (!c.staticMobility && c.speed * c.gmStepMs / 1000.0 > c.distance / 2))
      throw std::invalid_argument("dynamic step displacement must not exceed half horizontal box edge");
    if (mkdir(c.out.c_str(), 0755) != 0)
      throw std::runtime_error(std::string("result directory refused: ") + strerror(errno));
    std::ofstream config((c.out + "/config.txt").c_str());
    config << "n=" << c.n << "\ncoreNodes=" << (c.coreNodes ? c.coreNodes : c.n)
      << "\nprotocolModel=" << (c.cryptoAgreement ? "p256-prototype-no-registration" : "synthetic-noncryptographic")
      << "\ncryptoAgreement=" << c.cryptoAgreement << "\nstagedAgreement=" << c.stagedAgreement
      << "\nrouting=" << (c.olsr ? "OLSR" : "direct-on-link")
      << "\ninitiator=" << c.initiator << "\nseed=" << c.seed
      << "\np=" << c.loss << "\ncomputeMs=" << c.compute << "\nstartMs=" << c.start
      << "\ndurationMs=" << c.duration << "\nretryMs=" << c.retry
      << "\nmaterialRecordBytes=" << (c.cryptoAgreement ? 0 : 320)
      << "\nmaterialRecords=" << (c.cryptoAgreement ? 0 : c.n)
      << "\nlocalMaterialBytes=" << (c.cryptoAgreement ? 0 : 320 * c.n)
      << "\ngroupPayloadBytes=" << (c.cryptoAgreement ? 0 : 208 * c.n - 16)
      << "\npayloadSizeSemantics=" << (c.cryptoAgreement ? "variable-serialized-ciphertexts" : "fixed-synthetic")
      << "\ndistanceM=" << c.distance << "\nheightM=" << zMax << "\nspeedMps=" << c.speed
      << "\nalpha=" << c.alpha << "\ngmStepMs=" << c.gmStepMs
      << "\nwifi=802.11b\nphyMode=DsssRate5_5Mbps\ntxPowerDbm=20"
      << "\npathLoss=Friis+Nakagami+LogNormalShadowing+Range"
      << "\nfrequencyHz=2400000000\nsystemLoss=1\nminLossDb=0"
      << "\nshadowingMeanDb=0\nshadowingVarianceDb2=16\nmaxRangeM=" << maxRange
      << "\nmobility=" << (c.staticMobility ? "ConstantPosition" : "GaussMarkov")
      << "\nposition=RandomBox\naddressBase=10.1.1.0/24"
      << "\nappendPaceMs=" << c.appendPaceMs << "\nappendPaceSlots=50\nappendPaceBudget=4194304"
      << "\nappendRetryMs=" << c.appendRetryMs << "\nappendRetryMaxMs=" << c.appendRetryMaxMs
      << "\nheartbeatMs=100\nelectionMinMs=" << c.electionBase
      << "\nelectionMaxMs=" << 2 * c.electionBase - 1 << "\npresetArp=" << c.presetArp
      << "\ntimingVersion=3\nretryPolicy=local-leader-else-round-robin\nmodel=synthetic-GKA/dynamic-80211b-adhoc\n"
      << "rngRun=" << c.rngRun << "\nstaticMobility=" << c.staticMobility
      << "\ntrajectoryIntervalMs=100\npositionStreamStart=10000\nmobilityStreamStart=20000\n"
      << "applicationRng=mt19937-seed_seq(seed,rngRun,node,domain);election=1;drop=2\n";
    std::ofstream transport((c.out + "/transport.csv").c_str());
    if (!transport) throw std::runtime_error("transport output open failed");
    transport << "time_ns,node,action,peer,source,serial,total,part,count,status\n";
    std::ofstream events((c.out + "/events.csv").c_str());
    std::ofstream counts((c.out + "/nodes.csv").c_str());
    std::ofstream summary((c.out + "/summary.txt").c_str());
    if (!config || !events || !counts || !summary) throw std::runtime_error("output open failed");
    events << "time_ms,node,event,term,commit_index,time_ns,request,index,attempt,target\n";
    counts << "node,tx_datagrams,tx_bytes,rx_datagrams,rx_bytes,injected_drop,rejected,reassembled,expired,send_errors,applications,client_attempts\n";
    RngSeedManager::SetSeed(c.seed); RngSeedManager::SetRun(c.rngRun);
    NodeContainer nodes; nodes.Create(c.n);
    const std::string phyMode = "DsssRate5_5Mbps";
    Config::SetDefault("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue("2200"));
    Config::SetDefault("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue("2200"));
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));
    WifiHelper wifi; wifi.SetStandard(WIFI_PHY_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue(phyMode),
                                 "ControlMode", StringValue(phyMode));
    YansWifiPhyHelper phy = YansWifiPhyHelper::Default();
    phy.Set("TxPowerStart", DoubleValue(20.0));
    phy.Set("TxPowerEnd", DoubleValue(20.0));
    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::FriisPropagationLossModel",
      "Frequency", DoubleValue(2.4e9), "SystemLoss", DoubleValue(1.0),
      "MinLoss", DoubleValue(0.0));
    channel.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
    channel.AddPropagationLoss("ns3::RandomPropagationLossModel",
      "Variable", StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=16.0]"));
    channel.AddPropagationLoss("ns3::RangePropagationLossModel",
      "MaxRange", DoubleValue(maxRange));
    phy.SetChannel(channel.Create());
    WifiMacHelper mac; mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);
    const int64_t wifiStreams = wifi.AssignStreams(devices, 10);
    if (10 + wifiStreams > 10000) throw std::runtime_error("WiFi stream overlap");
    config << "wifiStreamStart=10\nwifiStreamCount=" << wifiStreams << '\n';
    std::ostringstream box, zbox;
    box << "ns3::UniformRandomVariable[Min=0.0|Max=" << c.distance << "]";
    zbox << "ns3::UniformRandomVariable[Min=0.0|Max=" << zMax << "]";
    std::ostringstream velocity, direction;
    velocity << "ns3::UniformRandomVariable[Min=" << c.speed << "|Max=" << c.speed << "]";
    direction << "ns3::UniformRandomVariable[Min=0.0|Max=6.283185307179586]";
    MobilityHelper mobility;
    Ptr<RandomBoxPositionAllocator> positions = CreateObject<RandomBoxPositionAllocator>();
    positions->SetAttribute("X", StringValue(box.str()));
    positions->SetAttribute("Y", StringValue(box.str()));
    positions->SetAttribute("Z", StringValue(zbox.str()));
    const int64_t positionStreams = positions->AssignStreams(10000);
    if (10000 + positionStreams > 20000) throw std::runtime_error("position stream overlap");
    config << "positionStreamCount=" << positionStreams << '\n';
    mobility.SetPositionAllocator(positions);
    if (c.staticMobility) mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    else mobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
      "Bounds", BoxValue(Box(0, c.distance, 0, c.distance, 0, zMax)),
      "TimeStep", TimeValue(MilliSeconds(c.gmStepMs)),
      "Alpha", DoubleValue(c.alpha),
      "MeanVelocity", StringValue(velocity.str()),
      "MeanDirection", StringValue(direction.str()),
      "MeanPitch", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=0.0]"),
      "NormalVelocity", StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=0.0|Bound=0.0]"),
      "NormalDirection", StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]"),
      "NormalPitch", StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=0.0|Bound=0.0]"));
    mobility.Install(nodes);
    config << "mobilityStreamCount=" << mobility.AssignStreams(nodes, 20000)
           << "\nsegmentBoundaryCheck=every-CourseChange\n";
    if (!c.staticMobility)
      for (uint32_t i = 0; i < c.n; ++i)
        nodes.Get(i)->GetObject<MobilityModel>()->TraceConnectWithoutContext("CourseChange",
          MakeBoundCallback(&CheckSegment, c.distance, zMax, c.gmStepMs / 1000.0));
    std::ofstream tracks((c.out + "/positions.csv").c_str());
    tracks << "time_ms,node,x,y,z,vx,vy,vz,time_ns\n" << std::setprecision(17);
    if (!tracks) throw std::runtime_error("output open failed");
    Simulator::ScheduleNow(&Track, nodes, &tracks, c.duration);
    InternetStackHelper internet;
    if (c.olsr) {
      OlsrHelper olsr;
      Ipv4StaticRoutingHelper staticRouting;
      Ipv4ListRoutingHelper routing;
      routing.Add(olsr, 10);
      routing.Add(staticRouting, 0);
      internet.SetRoutingHelper(routing);
    }
    internet.Install(nodes);
    Ipv4AddressHelper address; address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ips = address.Assign(devices);
    if (c.presetArp) {
      for (uint32_t i = 0; i < c.n; ++i) {
        Ptr<Ipv4L3Protocol> ip = nodes.Get(i)->GetObject<Ipv4L3Protocol>();
        Ptr<ArpCache> cache = ip->GetInterface(ip->GetInterfaceForDevice(devices.Get(i)))->GetArpCache();
        for (uint32_t j = 0; j < c.n; ++j) if (j != i) {
          ArpCache::Entry* entry = cache->Add(ips.GetAddress(j));
          entry->SetMacAddresss(devices.Get(j)->GetAddress());
          entry->MarkPermanent();
        }
      }
    }
    std::ofstream drops((c.out + "/drops.csv").c_str());
    drops << "time_ns,node,layer,uid,bytes\n";
    std::ofstream phyTx((c.out + "/phy-tx.csv").c_str());
    phyTx << "time_ns,node,layer,uid,bytes\n";
    for (uint32_t i = 0; i < c.n; ++i) {
      nodes.Get(i)->GetObject<ArpL3Protocol>()->TraceConnectWithoutContext("Drop",
          MakeBoundCallback(&DropTrace, &drops, i, std::string("arp")));
      Ptr<WifiNetDevice> dev = DynamicCast<WifiNetDevice>(devices.Get(i));
      const bool phyConnected = dev->GetPhy()->TraceConnectWithoutContext("PhyTxBegin",
          MakeBoundCallback(&DropTrace, &phyTx, i, std::string("phy_tx_begin")));
      config << "phyTxBeginConnected." << i << '=' << phyConnected << '\n';
      dev->GetPhy()->TraceConnectWithoutContext("PhyTxDrop",
          MakeBoundCallback(&DropTrace, &drops, i, std::string("phy_tx")));
      dev->GetPhy()->TraceConnectWithoutContext("PhyRxDrop",
          MakeBoundCallback(&DropTrace, &drops, i, std::string("phy_rx")));
      dev->GetMac()->TraceConnectWithoutContext("MacTxDrop",
          MakeBoundCallback(&DropTrace, &drops, i, std::string("mac_tx")));
    }
    std::vector<std::unique_ptr<Peer> > peers;
    for (uint32_t i = 0; i < c.n; ++i)
      peers.push_back(std::unique_ptr<Peer>(new Peer(i, c, ips, nodes.Get(i), events, transport)));
    if (c.cryptoAgreement) {
      daagka::Bytes session = daagka::random_bytes(32);
      std::vector<std::unique_ptr<daagka::Member> > members;
      std::vector<daagka::PublicMember> roster;
      for (uint32_t i = 0; i < c.n; ++i) {
        members.push_back(std::unique_ptr<daagka::Member>(new daagka::Member("uav-" + std::to_string(i))));
        roster.push_back({members.back()->id, members.back()->public_key, {}, {}});
      }
      std::sort(roster.begin(), roster.end(), [](const daagka::PublicMember& a,
                                                   const daagka::PublicMember& b) { return a.id < b.id; });
      for (auto& item : roster) {
        const uint32_t i = static_cast<uint32_t>(std::stoul(item.id.substr(4)));
        daagka::Proof proof = daagka::prove(*members[i], session, roster);
        item.commitment = proof.commitment;
        item.response = proof.response;
      }
      daagka::verify_roster(session, roster);
      for (uint32_t i = 0; i < c.n; ++i)
        peers[i]->ConfigureCrypto(session, roster, std::move(members[i]));
    }
    for (uint32_t i = 0; i < c.n; ++i)
      Simulator::Schedule(MilliSeconds(0), &Peer::Tick, peers[i].get());
    Simulator::Stop(MilliSeconds(c.duration)); Simulator::Run();
    Track(nodes, &tracks, c.duration);
    for (size_t i = 0; i < peers.size(); ++i) peers[i]->Summary(counts);
    const bool ok = peers[c.initiator]->Confirmed();
    summary << "status=" << (ok ? "confirmed" : "timeout_unknown") << '\n';
    peers[c.initiator]->Timing(summary);
    std::cout << "n=" << c.n << " p=" << c.loss << " seed=" << c.seed << " status="
              << (ok ? "confirmed" : "timeout_unknown") << '\n';
    peers[c.initiator]->Timing(std::cout);
    Simulator::Destroy(); return ok ? 0 : 2;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
