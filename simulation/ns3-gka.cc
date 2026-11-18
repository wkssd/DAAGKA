#include "../uav-node/ns3-peer.h"
#include "ns3-fault.h"
#include "ns3/propagation-delay-model.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-module.h"
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#include <cmath>

static void CheckSegment(double edge, double height, double step, Ptr<const MobilityModel> model) {
  const Vector p = model->GetPosition(), v = model->GetVelocity();
  const Vector end(p.x + v.x * step, p.y + v.y * step, p.z + v.z * step);
  if (p.x < -1e-8 || p.x > edge + 1e-8 || p.y < -1e-8 || p.y > edge + 1e-8 ||
      p.z < -1e-8 || p.z > height + 1e-8 || end.x < -1e-8 || end.x > edge + 1e-8 ||
      end.y < -1e-8 || end.y > edge + 1e-8 || end.z < -1e-8 || end.z > height + 1e-8)
    throw std::runtime_error("actual GM segment outside configured bounds");
}

int main(int argc, char** argv) {
  try {
    Settings c; CommandLine cmd;
    cmd.AddValue("n", "UAV count, 3..50", c.n);
    cmd.Parse(argc, argv);
    c.out = "DAAGKA-n" + std::to_string(c.n);
    c.Resolve();
    if (!std::isfinite(c.distance) || c.distance<=0 || c.distance>100000 ||
        !std::isfinite(c.height) || c.height<=0 || c.height>100000 ||
        !std::isfinite(c.speedMin) || !std::isfinite(c.speedMax) ||
        c.speedMin<0 || c.speedMax>100 || c.speedMin>c.speedMax ||
        !std::isfinite(c.alpha) || c.alpha<0 || c.alpha>=1 ||
        !c.gmStepMs || c.gmStepMs>60000)
      throw std::invalid_argument("invalid network parameters");
    const double zMax = c.height;
    const double maxRange = std::sqrt(2.0 * c.distance * c.distance + zMax * zMax);
    // NS3.25 reverses once per step: <= half the box edge guarantees the
    // reversed endpoint is inside too. No output or mobility clipping is used.
    if (!c.rngRun || (!c.staticMobility && c.speedMax * c.gmStepMs / 1000.0 > c.distance / 2))
      throw std::invalid_argument("dynamic step displacement must not exceed half horizontal box edge");
    if (mkdir(c.out.c_str(), 0755) != 0)
      throw std::runtime_error(std::string("result directory refused: ") + strerror(errno));
    std::ofstream summary((c.out + "/summary.txt").c_str());
    summary << "n=" << c.n << "\nvoters=" << c.n
      << "\nschemaVersion=5\nstages=2\nconfirmation=local-apply\nbusinessReplies=0"
      << "\nprotocolModel=paper-gka-openssl"
      << "\nrouting=" << (c.olsr ? "OLSR" : "direct-on-link")
      << "\ninitiator=" << c.initiator << "\nseed=" << c.seed
      << "\np=" << c.loss << "\nprepareMs=" << c.prepareMs << "\nderiveMs=" << c.deriveMs
      << "\nrounds=" << c.rounds << "\nselectionBytes=" << c.selectionBytes
      << "\nmaterialBytes=" << c.materialBytes << "\nstartMs=" << c.start
      << "\ndurationMs=" << c.duration << "\nretryMs=" << c.retry
      << "\npayloadSizeSemantics=value-bytes-excluding-request-and-headers"
      << "\ndistanceM=" << c.distance << "\nheightM=" << zMax
      << "\nspeedMinMps=" << c.speedMin << "\nspeedMaxMps=" << c.speedMax
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
      << "\ntimingVersion=4\nretryPolicy=local-leader-else-round-robin\nmodel=paper-GKA-OpenSSL/dynamic-80211b-adhoc\n"
      << "rngRun=" << c.rngRun << "\nstaticMobility=" << c.staticMobility
      << "\npositionStreamStart=10000\nmobilityStreamStart=20000\n"
      << "applicationRng=mt19937-seed_seq(seed,rngRun,node,domain);election=1;drop=2\n";
    summary << "cryptoRng=OpenSSL-RAND\ncryptoTiming=modeled-waits-separate-from-host-cpu\n"
           << "trustedSetup=preconfigured-fixed-roster-and-parameters\n";
    summary << "arpDeadMs=" << c.arpDeadMs << '\n';
    summary << "isolateNodes=\ndisconnectAtMs=0\nreconnectAtMs=0\n";
    if (!summary) throw std::runtime_error("output open failed");
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
    Ptr<YansWifiChannel> channel=CreateObject<YansWifiChannel>();
    channel->SetPropagationDelayModel(CreateObject<ConstantSpeedPropagationDelayModel>());
    Ptr<FriisPropagationLossModel> friis=CreateObject<FriisPropagationLossModel>();
    friis->SetAttribute("Frequency",DoubleValue(2.4e9));
    friis->SetAttribute("SystemLoss",DoubleValue(1));
    friis->SetAttribute("MinLoss",DoubleValue(0));
    Ptr<NakagamiPropagationLossModel> nakagami=CreateObject<NakagamiPropagationLossModel>();
    Ptr<RandomPropagationLossModel> shadowing=CreateObject<RandomPropagationLossModel>();
    shadowing->SetAttribute("Variable",StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=16.0]"));
    Ptr<RangePropagationLossModel> range=CreateObject<RangePropagationLossModel>();
    range->SetAttribute("MaxRange",DoubleValue(maxRange));
    Ptr<IsolationLossModel> gate=CreateObject<IsolationLossModel>();
    friis->SetNext(nakagami);nakagami->SetNext(shadowing);shadowing->SetNext(range);range->SetNext(gate);
    channel->SetPropagationLossModel(friis);phy.SetChannel(channel);
    WifiMacHelper mac; mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);
    const int64_t wifiStreams = wifi.AssignStreams(devices, 10);
    const int64_t propagationStreams=channel->AssignStreams(50000);
    summary << "propagationStreamStart=50000\npropagationStreamCount=" << propagationStreams << '\n';
    if (10 + wifiStreams > 10000) throw std::runtime_error("WiFi stream overlap");
    summary << "wifiStreamStart=10\nwifiStreamCount=" << wifiStreams << '\n';
    std::ostringstream box, zbox;
    box << "ns3::UniformRandomVariable[Min=0.0|Max=" << c.distance << "]";
    zbox << "ns3::UniformRandomVariable[Min=0.0|Max=" << zMax << "]";
    std::ostringstream velocity, direction;
    velocity << "ns3::UniformRandomVariable[Min=" << c.speedMin << "|Max=" << c.speedMax << "]";
    direction << "ns3::UniformRandomVariable[Min=0.0|Max=6.283185307179586]";
    MobilityHelper mobility;
    Ptr<RandomBoxPositionAllocator> positions = CreateObject<RandomBoxPositionAllocator>();
    positions->SetAttribute("X", StringValue(box.str()));
    positions->SetAttribute("Y", StringValue(box.str()));
    positions->SetAttribute("Z", StringValue(zbox.str()));
    const int64_t positionStreams = positions->AssignStreams(10000);
    if (10000 + positionStreams > 20000) throw std::runtime_error("position stream overlap");
    summary << "positionStreamCount=" << positionStreams << '\n';
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
    summary << "mobilityStreamCount=" << mobility.AssignStreams(nodes, 20000)
           << "\nsegmentBoundaryCheck=every-CourseChange\n";
    if (!c.staticMobility)
      for (uint32_t i = 0; i < c.n; ++i)
        nodes.Get(i)->GetObject<MobilityModel>()->TraceConnectWithoutContext("CourseChange",
          MakeBoundCallback(&CheckSegment, c.distance, zMax, c.gmStepMs / 1000.0));
    Config::SetDefault("ns3::ArpCache::DeadTimeout",TimeValue(MilliSeconds(c.arpDeadMs)));
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
    summary << "internetStreamStart=30000\ninternetStreamCount=" << internet.AssignStreams(nodes,30000) << '\n';
    if(c.olsr) {OlsrHelper olsr;summary << "olsrStreamStart=40000\nolsrStreamCount=" << olsr.AssignStreams(nodes,40000) << '\n';}
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
    GkaSetup setup(c);
    std::vector<std::unique_ptr<Peer> > peers;
    for (uint32_t i = 0; i < c.n; ++i)
      peers.push_back(std::unique_ptr<Peer>(new Peer(i, c, ips, nodes.Get(i),
                                                  setup.selections, std::move(setup.privateKeys[i]))));
    peers[c.initiator]->SetRoundCompleteCallback([&peers,&c](NodeId node,uint64_t round) {
      if(node==c.initiator && round<c.rounds)
        Simulator::ScheduleNow(&Peer::StartRound,peers[node].get(),round+1);
    });
    Simulator::Schedule(MilliSeconds(c.start),&Peer::StartRound,peers[c.initiator].get(),uint64_t(1));
    for (uint32_t i = 0; i < c.n; ++i)
      Simulator::Schedule(MilliSeconds(0), &Peer::Tick, peers[i].get());
    Simulator::Stop(MilliSeconds(c.duration)); Simulator::Run();
    uint64_t completed=0;
    for(const auto& peer:peers) completed+=peer->CompletedRounds();
    const uint64_t expected=uint64_t(c.n)*c.rounds;
    uint64_t digestCount=0;
    bool mismatch=false;
    std::ostringstream keyRows;
    // Observation only: no global key comparison enters a peer's protocol state.
    for(uint64_t round=1;round<=c.rounds;++round) {
      std::set<std::string> digests;
      for(NodeId node=0;node<c.n;++node) {
        const std::string digest=peers[node]->GroupKeyDigest(round);
        if(digest.empty()) continue;
        keyRows<<round<<','<<node<<','<<digest<<'\n';
        digests.insert(digest);++digestCount;
      }
      if(digests.size()>1) mismatch=true;
    }
    const bool missing=digestCount!=completed;
    const std::string keyStatus=mismatch?"mismatch":missing?"missing":digestCount?"consistent":"not_observed";
    const bool keyError=mismatch || missing;
    const bool ok=completed==expected && !keyError;
    const std::string status=keyError?"key_error":ok?"complete":"incomplete";
    summary << "status=" << status
            << "\ncompletedNodeRounds=" << completed << "\nexpectedNodeRounds=" << expected
            << "\nkeyConsistency=" << keyStatus << "\nkeyDigestNodeRounds=" << digestCount
            << "\nround,node,key_digest\n" << keyRows.str();
    std::cout << "n=" << c.n << " status=" << status
              << " completed=" << completed << "/" << expected << " keyConsistency=" << keyStatus << '\n';
    Simulator::Destroy(); return keyError?1:ok?0:2;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
