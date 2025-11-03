/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// Authors:
// Zhuowen Li
#include "ns3/applications-module.h"
#include "ns3/config-store-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/propagation-module.h"
#include "ns3/trace-helper.h"
#include "ns3/wifi-module.h"
#include "ns3/stats-module.h"
#include <string>
#include <vector>
#include <sys/stat.h>
#include <fstream>  // 添加文件流头文件
#include <iomanip>  // 添加iomanip头文件
#include <sqlite3.h> // 添加SQLite3头文件

#include "AdhocUdpApplication.h"
#include "SimulationDatabase.h" // 添加我们的数据库头文件

using namespace ns3;

// Log部件键名
NS_LOG_COMPONENT_DEFINE("wifi-adhoc-UAV-experiment");

// --------- 实验具体数据 -------------
// 数据速率
// std::string phyMode("DsssRate11Mbps");
std::string phyMode("ErpOfdmRate12Mbps");  // 802.11g的ERP-OFDM调制方式，传输速率12Mbps
// 传播损失模型 和 传播延迟模型
std::string propagationLossModel("ns3::FriisPropagationLossModel");
std::string propagationDelayModel("ns3::ConstantSpeedPropagationDelayModel");
// 节点运动速度 和 运动模型
std::string mobilitySpeed("ns3::UniformRandomVariable[Min=10|Max=50]");
std::string mobilityModel("ns3::GaussMarkovMobilityModel");
// 活动范围(矩阵)
double areaLength = 500;   // 活动区域长度 (m)
double areaWidth = 500;    // 活动区域宽度 (m)
double areaHeight = 100;   // 活动区域高度 (m) - 无人机飞行高度限制
// 节点个数
uint32_t numNodes = 5;
// 仿真时间
uint32_t simuTime = 30;
// 周期性广播间隔（秒）
double periodicInterval = 0.01;  
// 完成时间
double CompletionTime = 0;
// 数据库文件名
std::string dbFileName = "data.db";  // 默认数据库文件名

// ------------ End -----------------

// ---------- 实验数据记录标签 ----------
// 实验内容
std::string experiment;
// 实验参数
std::string strategy;
// 实验节点数
std::string input;
// 实验序号
std::string runId;
// ------------- End -----------------

// 检查是否所有节点都完成了密钥收集
bool CheckAllNodesCompleted(const NodeContainer& nodes) {
	for (uint32_t i = 0; i < nodes.GetN(); i++) {
		Ptr<AppReceiver> receiver = DynamicCast<AppReceiver>(nodes.Get(i)->GetApplication(1));
		if (!receiver->IsCompleted()) {
			return false;
		}
	}
	// 所有节点都已完成，返回true
	return true;
}

// 创建一个定期检查函数，当所有节点都完成时停止模拟,从第一秒之后开始检查
void CheckCompletionAndStop(const NodeContainer& nodes) {
	if (CheckAllNodesCompleted(nodes)) {
		CompletionTime = Simulator::Now().GetSeconds() - 1.0;
		NS_LOG_INFO("密钥协商完成时间: " << CompletionTime << " 秒");
		Simulator::Stop();
	} else {
		NS_LOG_INFO("继续检查");
		// 如果没有全部完成，则在0.1秒后继续检查
		Simulator::Schedule(Seconds(0.1), &CheckCompletionAndStop, nodes);
	}
}

// 四档链路质量
// void SetupLinkQuality (YansWifiPhyHelper &wifiPhy, std::string quality)
// {
//   /* ====== HIGH ====== */
//   if (quality == "high")
//     {
//       wifiPhy.Set ("TxPowerStart",       DoubleValue (20.0));   // ↑功率
//       wifiPhy.Set ("TxPowerEnd",         DoubleValue (20.0));
//     //   wifiPhy.Set ("RxSensitivity",      DoubleValue (-84.0));  // 12 Mb/s 常见规格
//       wifiPhy.Set ("CcaMode1Threshold",  DoubleValue (-80.0));  // 灵敏度+4 dB

//       YansWifiChannelHelper ch;
//       ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
//       ch.AddPropagationLoss  ("ns3::FriisPropagationLossModel",
//                               "Frequency", DoubleValue (2.4e9));
//       // 轻微快衰落，让 RSSI 有小抖动
//       ch.AddPropagationLoss  ("ns3::NakagamiPropagationLossModel",
//                               "m0", DoubleValue (3.0));         // LoS UAV-UAV
//       wifiPhy.SetChannel (ch.Create ());
//     }

//   /* ====== MEDIUM ====== */
//   else if (quality == "medium")
//     {
//       wifiPhy.Set ("TxPowerStart",       DoubleValue (17.0));
//       wifiPhy.Set ("TxPowerEnd",         DoubleValue (17.0));
//     //   wifiPhy.Set ("RxSensitivity",      DoubleValue (-84.0));
//       wifiPhy.Set ("CcaMode1Threshold",  DoubleValue (-81.0));

//       YansWifiChannelHelper ch;
//       ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
//       ch.AddPropagationLoss  ("ns3::LogDistancePropagationLossModel",
//                               "Exponent",          DoubleValue (2.7),
//                               "ReferenceDistance", DoubleValue (1.0),
//                               "ReferenceLoss",     DoubleValue (40.05));
//       ch.AddPropagationLoss  ("ns3::RandomPropagationLossModel",
//                               "Variable", StringValue ("ns3::NormalRandomVariable[Mean=0|Variance=16]")); // σ=4 dB
//       ch.AddPropagationLoss  ("ns3::NakagamiPropagationLossModel",
//                               "m0", DoubleValue (1.0),
//                               "m1", DoubleValue (1.0),
//                               "m2", DoubleValue (0.9),
//                               "Distance1", DoubleValue (150.0),
//                               "Distance2", DoubleValue (400.0));
//       wifiPhy.SetChannel (ch.Create ());
//     }

//   /* ====== LOW ====== */
//   else if (quality == "low")
//     {
//       wifiPhy.Set ("TxPowerStart",       DoubleValue (14.0));
//       wifiPhy.Set ("TxPowerEnd",         DoubleValue (14.0));
//     //   wifiPhy.Set ("RxSensitivity",      DoubleValue (-84.0));
//       wifiPhy.Set ("CcaMode1Threshold",  DoubleValue (-78.0));   // 稍高，避免卡住发包

//       YansWifiChannelHelper ch;
//       ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
//       ch.AddPropagationLoss  ("ns3::LogDistancePropagationLossModel",
//                               "Exponent",          DoubleValue (3.0),
//                               "ReferenceDistance", DoubleValue (1.0),
//                               "ReferenceLoss",     DoubleValue (46.7));
//       ch.AddPropagationLoss  ("ns3::RandomPropagationLossModel",
//                               "Variable", StringValue ("ns3::NormalRandomVariable[Mean=0|Variance=36]")); // σ=6 dB
//       ch.AddPropagationLoss  ("ns3::NakagamiPropagationLossModel",
//                               "m0", DoubleValue (1.0),
//                               "m1", DoubleValue (0.8),
//                               "m2", DoubleValue (0.75),
//                               "Distance1", DoubleValue (200.0),
//                               "Distance2", DoubleValue (500.0));
//       wifiPhy.SetChannel (ch.Create ());
//     }

//   /* ====== VERY POOR ====== */
//   else if (quality == "very_poor")
//     {
//       wifiPhy.Set ("TxPowerStart",       DoubleValue ( 8.0));
//       wifiPhy.Set ("TxPowerEnd",         DoubleValue ( 8.0));
//     //   wifiPhy.Set ("RxSensitivity",      DoubleValue (-84.0));
//       wifiPhy.Set ("CcaMode1Threshold",  DoubleValue (-75.0));

//       YansWifiChannelHelper ch;
//       ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
//       ch.AddPropagationLoss  ("ns3::ThreeLogDistancePropagationLossModel",
//                               "Distance0",  DoubleValue (1.0),
//                               "Distance1",  DoubleValue (150.0),
//                               "Distance2",  DoubleValue (400.0),
//                               "Exponent0",  DoubleValue (2.2),
//                               "Exponent1",  DoubleValue (3.0),
//                               "Exponent2",  DoubleValue (4.5));
//       ch.AddPropagationLoss  ("ns3::RandomPropagationLossModel",
//                               "Variable", StringValue ("ns3::NormalRandomVariable[Mean=0|Variance=81]")); // σ=9 dB
//       ch.AddPropagationLoss  ("ns3::NakagamiPropagationLossModel",
//                               "m0", DoubleValue (1.0),
//                               "m1", DoubleValue (0.7),
//                               "m2", DoubleValue (0.6));
//       ch.AddPropagationLoss  ("ns3::RangePropagationLossModel",
//                               "MaxRange", DoubleValue (400.0));  // 400 m 外直接失联
//       wifiPhy.SetChannel (ch.Create ());
//     }
// }


void SetupLinkQuality (YansWifiPhyHelper &wifiPhy, std::string quality)
{
  /* 硬件常量 */
  wifiPhy.Set ("RxNoiseFigure", DoubleValue (7.0));   // 无人机常见 NF≈7 dB
  wifiPhy.Set ("RxGain",        DoubleValue (2.0));   // +2 dBi 小型天线

  /* ========== HIGH ==========  (LoS 0-150 m) */
  if (quality == "high")
    {
      wifiPhy.Set ("TxPowerStart", DoubleValue (20.0));   // 20 dBm
      wifiPhy.Set ("TxPowerEnd",   DoubleValue (20.0));
      wifiPhy.Set ("CcaMode1Threshold", DoubleValue (-82.0));   // RxSens-84 +2 dB

      YansWifiChannelHelper ch;
      ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
      ch.AddPropagationLoss ("ns3::FriisPropagationLossModel",
                             "Frequency", DoubleValue (2.4e9));
      ch.AddPropagationLoss ("ns3::RandomPropagationLossModel",
                             "Variable", StringValue ("ns3::NormalRandomVariable[Mean=0|Variance=4]"));   // σ=2 dB
      ch.AddPropagationLoss ("ns3::NakagamiPropagationLossModel",
                             "m0", DoubleValue (2.5));   // 轻微快衰落
      ch.AddPropagationLoss ("ns3::RangePropagationLossModel",
                             "MaxRange", DoubleValue (1200.0));   // 1.2 km
      wifiPhy.SetChannel (ch.Create ());
    }

  /* ========== MEDIUM ==========  (轻遮挡 150-600 m) */
  else if (quality == "medium")
    {
      wifiPhy.Set ("TxPowerStart", DoubleValue (18.0));
      wifiPhy.Set ("TxPowerEnd",   DoubleValue (18.0));
      wifiPhy.Set ("CcaMode1Threshold", DoubleValue (-81.0));

      YansWifiChannelHelper ch;
      ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
      ch.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
                             "Exponent",          DoubleValue (2.5),
                             "ReferenceDistance", DoubleValue (1.0),
                             "ReferenceLoss",     DoubleValue (40.05));
      ch.AddPropagationLoss ("ns3::RandomPropagationLossModel",
                             "Variable", StringValue ("ns3::NormalRandomVariable[Mean=0|Variance=25]")); // σ=5 dB
      ch.AddPropagationLoss ("ns3::NakagamiPropagationLossModel",
                             "m0", DoubleValue (1.5),
                             "m1", DoubleValue (1.2),
                             "m2", DoubleValue (1.0),
                             "Distance1", DoubleValue (150.0),
                             "Distance2", DoubleValue (400.0));
      ch.AddPropagationLoss ("ns3::RangePropagationLossModel",
                             "MaxRange", DoubleValue (700.0));
      wifiPhy.SetChannel (ch.Create ());
    }

  /* ========== LOW ==========  (远距 / 频繁遮挡) */
  else if (quality == "low")
    {
      wifiPhy.Set ("TxPowerStart", DoubleValue (14.0));
      wifiPhy.Set ("TxPowerEnd",   DoubleValue (14.0));
      wifiPhy.Set ("CcaMode1Threshold", DoubleValue (-78.0));

      YansWifiChannelHelper ch;
      ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
      ch.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
                             "Exponent",          DoubleValue (3.2),
                             "ReferenceDistance", DoubleValue (1.0),
                             "ReferenceLoss",     DoubleValue (46.7));
      ch.AddPropagationLoss ("ns3::RandomPropagationLossModel",
                             "Variable", StringValue ("ns3::NormalRandomVariable[Mean=0|Variance=49]")); // σ=7 dB
      ch.AddPropagationLoss ("ns3::NakagamiPropagationLossModel",
                             "m0", DoubleValue (1.0),
                             "m1", DoubleValue (0.8),
                             "m2", DoubleValue (0.7),
                             "Distance1", DoubleValue (200.0),
                             "Distance2", DoubleValue (500.0));
      ch.AddPropagationLoss ("ns3::RangePropagationLossModel",
                             "MaxRange", DoubleValue (600.0));
      wifiPhy.SetChannel (ch.Create ());
    }

  /* ========== VERY POOR ==========  (NLoS / 密集遮挡) */
  else   /* very_poor */
    {
      wifiPhy.Set ("TxPowerStart", DoubleValue (10.0));
      wifiPhy.Set ("TxPowerEnd",   DoubleValue (10.0));
      wifiPhy.Set ("CcaMode1Threshold", DoubleValue (-75.0));

      YansWifiChannelHelper ch;
      ch.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
	  // 设置传播损失
      ch.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
                             "Exponent",          DoubleValue (3.9),
                             "ReferenceDistance", DoubleValue (1.0),
                             "ReferenceLoss",     DoubleValue (46.7));
      // 设置随机传播损失
      ch.AddPropagationLoss ("ns3::RandomPropagationLossModel",
                             "Variable", StringValue ("ns3::NormalRandomVariable[Mean=0|Variance=81]")); // σ=9 dB
      ch.AddPropagationLoss ("ns3::NakagamiPropagationLossModel",
                             "m0", DoubleValue (1.0),
                             "m1", DoubleValue (0.7),
                             "m2", DoubleValue (0.6),
                             "Distance1", DoubleValue (150.0),
                             "Distance2", DoubleValue (400.0));
      ch.AddPropagationLoss ("ns3::RangePropagationLossModel",
                             "MaxRange", DoubleValue (400.0));
      wifiPhy.SetChannel (ch.Create ());
    }
}


void startSimulation(const std::string& linkQuality) {
    
	NodeContainer nodes;
	nodes.Create(numNodes);

	// --------------------------------------------------------------
	// ---------- 设置物理层、数据链路层 ----------
	// --------------------------------------------------------------
	// 设置wifi标准
	WifiHelper wifi;
	// wifi.SetStandard(WIFI_PHY_STANDARD_80211b);
	wifi.SetStandard(WIFI_PHY_STANDARD_80211g);  // 使用802.11g标准

	// 设置物理层-PHY层
	YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
	// wireshark抓包需开启
	// wifiPhy.SetPcapDataLinkType(YansWifiPhyHelper::DLT_IEEE802_11_RADIO);

	// 设置链路质量
	SetupLinkQuality(wifiPhy, linkQuality);

	// 设置数据链路层-MAC层
	NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default();
	// 设置速率控制
	// wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
	// 		"DataMode", StringValue(phyMode),
	// 		"ControlMode", StringValue(phyMode));
	wifi.SetRemoteStationManager("ns3::MinstrelWifiManager");		//链路恶化时会自动退速
	// 设置模式
	wifiMac.SetType("ns3::AdhocWifiMac");

	// 安装至设备
	NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, nodes);
	// -------------- End ----------------


	// ------------------------------------------------------------
	// ---------- 设置网络层、传输层协议 -------------
	// ------------------------------------------------------------
	// 安装传输层
	InternetStackHelper internet;
	internet.Install(nodes);
	// 安装网络层，分配IP
	Ipv4AddressHelper ipv4;
	ipv4.SetBase("10.1.1.0", "255.255.255.0");
	Ipv4InterfaceContainer ipv4Container = ipv4.Assign(devices);
	// ------------- End -----------------


	// ------------------------------------------------------------
	// ---------- 设置应用层 -------------
	// ------------------------------------------------------------
	// 设置收包计数器
	Ptr<CounterCalculator<> > totalSentPackets = CreateObject<CounterCalculator<> >();
	// 设置发包计数器
	Ptr<CounterCalculator<> > totalRecvPackets = CreateObject<CounterCalculator<> >();
	totalSentPackets->SetKey("发送方");
	totalSentPackets->SetContext("发包总数");
	totalRecvPackets->SetKey("接收方");
	totalRecvPackets->SetContext("收包总数");

	// 设置应用层信息
	for (uint32_t i = 0; i < numNodes; i++) {
		Ptr<Node> nodeToInstallApp = nodes.Get(i);
		Ptr<AppSender> sender = CreateObject<AppSender>();
		Ptr<AppReceiver> receiver = CreateObject<AppReceiver>();

		sender->SetSendCounter(totalSentPackets);
		receiver->SetReceiveCounter(totalRecvPackets);
		// 为接收方设置网络节点个数，用于判断是否完成通信
		receiver->SetNumNodes(numNodes);
		// 设置节点ID用于标识
		receiver->SetNodeId(i);
        sender->SetNodeId(i);
        
        // 初始化
        receiver->SetNetworkSize(numNodes);
        sender->SetNetworkSize(numNodes);

		nodeToInstallApp->AddApplication(sender);
		nodeToInstallApp->AddApplication(receiver);

		receiver->SetStartTime(Seconds(0));
		// 注意，这里发送方必须把时间岔开，否则不能发送消息
		sender->SetStartTime(Seconds(1 + 0.00001 * i));

		receiver->SetStopTime(Seconds(simuTime));
		sender->SetStopTime(Seconds(simuTime));
	}
	// ------------- End -----------------


	// ------------------------------------------------------------
	// ---------- 设置移动模型 -------------
	// ------------------------------------------------------------
	MobilityHelper mobility;

	// RandomBoxPositionAllocator实现在一个立方体内任意选取位置
	Ptr<RandomBoxPositionAllocator> randPosLocator =
			CreateObject<RandomBoxPositionAllocator>();
	// 随机设置节点的位置
	std::ostringstream playGround;
	playGround << "ns3::UniformRandomVariable[Min=0.0|" << "Max=" << areaLength << "]";
	randPosLocator->SetAttribute("X", StringValue(playGround.str()));
	playGround.str("");
	playGround << "ns3::UniformRandomVariable[Min=0.0|" << "Max=" << areaWidth << "]";
	randPosLocator->SetAttribute("Y", StringValue(playGround.str()));
	playGround.str("");
	playGround << "ns3::UniformRandomVariable[Min=0.0|" << "Max=" << areaHeight << "]";
	randPosLocator->SetAttribute("Z", StringValue(playGround.str()));
	mobility.SetPositionAllocator(randPosLocator);

	// 设置移动模型
	mobility.SetMobilityModel(mobilityModel,									// 移动模型
			"Bounds", BoxValue(												// 边界
					Box(0, areaLength, 0, areaWidth, 0, areaHeight)),
			"Alpha", DoubleValue (0.85),										// 模型可调参数
			"TimeStep", TimeValue(Seconds(1)),								// 运动方向和速度改变间隔
			"MeanVelocity", StringValue(mobilitySpeed),						// 运动平均速度
			"MeanDirection", StringValue(										// 运动平均方向
					"ns3::UniformRandomVariable[Min=0|Max=6.283185307]"),
			"MeanPitch", StringValue(											// 平均??
					"ns3::UniformRandomVariable[Min=0.05|Max=0.05]"),
			"NormalVelocity", StringValue(										// 计算下一个随机速度值的随机变量
					"ns3::NormalRandomVariable[Mean=0.0|Variance=0.0|Bound=0.0]"),
			"NormalDirection", StringValue(									// 计算下一个随机方向的随机变量
					"ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]"),
			"NormalPitch", StringValue(										// 计算下一个随机??的随机变量
					"ns3::NormalRandomVariable[Mean=0.0|Variance=0.02|Bound=0.04]")
			);

	for (uint32_t i = 0; i < numNodes; ++i) {
		mobility.Install(nodes.Get(i));
	}
	// -------------- End ----------------


	// ------------------------------------------------------------
	// ---------- 实验数据收集 -------------
	// ------------------------------------------------------------
	// 创建一个数据收集器来收集本次实验数据
	DataCollector dataCollector;
	dataCollector.DescribeRun(experiment, strategy, input, runId);
	dataCollector.AddMetadata("author", "float");
	dataCollector.AddDataCalculator(totalSentPackets);
	dataCollector.AddDataCalculator(totalRecvPackets);
	// -------------- End ----------------


	// ------------------------------------------------------------
	// ---------- 开始仿真 -------------
	// ------------------------------------------------------------
    
	// 设置仿真结束时间
	Simulator::Stop(Seconds(simuTime));

	//从第1.1秒开始定期检查
	Simulator::Schedule(Seconds(1.1), &CheckCompletionAndStop, nodes);

	// 仿真开始
	Simulator::Run();

	// 统计数据包数量
	uint32_t totalSent = 0;
	uint32_t totalReceived = 0;
	uint32_t successfulNodes = 0; // 成功接收所有数据包的节点数
	// double keyAgreementDelay = 0; // 密钥协商完成时间

	
	// 用于记录每个节点的发送和接收包数（用于数据库记录）
	std::vector<uint32_t> sentPackets;
	std::vector<uint32_t> receivedPackets;
	sentPackets.reserve(numNodes);
	receivedPackets.reserve(numNodes);

	for (uint32_t i = 0; i < numNodes; i++) {
		// 获取接收方和发送方
		Ptr<AppReceiver> receiver = DynamicCast<AppReceiver>(nodes.Get(i)->GetApplication(1));
		Ptr<AppSender> sender = DynamicCast<AppSender>(nodes.Get(i)->GetApplication(0));
		// 获取接收方和发送方数据包数量
		uint32_t packetsReceived = receiver->GetReceivedPackets();
		NS_LOG_INFO("节点" << i << "接收到的数据包数量: " << packetsReceived);
		uint32_t packetsSent = sender->GetSentPackets();
		NS_LOG_INFO("节点" << i << "发送的数据包数量: " << packetsSent);
		
		// 保存每个节点的包数据（用于数据库记录）
		sentPackets.push_back(packetsSent);
		receivedPackets.push_back(packetsReceived);
		
		// 检查节点i是否收到所有密钥贡献
		if (receiver->IsCompleted()) {
			successfulNodes++;
			NS_LOG_INFO("节点" << i << "成功收集所有密钥贡献");
		}
		
		// 统计总发送和接收数据包数量	
		totalSent += packetsSent;
		totalReceived += packetsReceived;
	}
	// 输出每个节点接收到的数据包信息
	NS_LOG_INFO("------------节点数据包统计------------");
	NS_LOG_INFO("+--------+-------------+-------------+----------+");
	NS_LOG_INFO("| 节点ID | 发送数据包  | 接收数据包  | 是否完成 |");
	NS_LOG_INFO("+--------+-------------+-------------+----------+");
	NS_LOG_INFO("+--------+-------------+-------------+----------+");

	for (uint32_t i = 0; i < numNodes; i++) {
		Ptr<AppReceiver> receiver = DynamicCast<AppReceiver>(nodes.Get(i)->GetApplication(1));
		Ptr<AppSender> sender = DynamicCast<AppSender>(nodes.Get(i)->GetApplication(0));
		NS_LOG_INFO("| " << std::setw(6) << i << " | " << std::setw(11) << sender->GetSentPackets() << " | " << std::setw(11) << receiver->GetReceivedPackets() << " | " << (receiver->IsCompleted() ? "是" : "否") << " |");
	}

	// 输出汇总信息
	NS_LOG_INFO("汇总统计:");
	NS_LOG_INFO("  总发送数据包: " << totalSent);
	NS_LOG_INFO("  总接收数据包: " << totalReceived);
	// NS_LOG_INFO("  重复接收数据包: " << totalDuplicates);
	
	// 计算更多统计指标
	double avgSent = (double)totalSent / numNodes;
	double avgReceived = (double)totalReceived / numNodes;
	double overheadRatio = (totalSent > 0) ? (double)totalReceived / totalSent : 0;
	
	NS_LOG_INFO("分析指标:");
	NS_LOG_INFO("  平均每节点发送数据包: " << std::fixed << std::setprecision(2) << avgSent);
	NS_LOG_INFO("  平均每节点接收数据包: " << std::fixed << std::setprecision(2) << avgReceived);
	NS_LOG_INFO("  通信开销比(接收/发送): " << std::fixed << std::setprecision(2) << overheadRatio);
	
	// 计算成功率
	double successRate = (double)successfulNodes / numNodes * 100;
	NS_LOG_INFO("  成功接收所有数据包的节点比例: " << successfulNodes << "/" << numNodes 
				<< " (" << successRate << "%)");
	NS_LOG_INFO("----------------------------------------");
    
	// 密钥协商完成的时延，模拟结束时间减去1秒（初始延迟）
	NS_LOG_INFO("密钥协商完成时延: " << CompletionTime << " 秒");
	
	// 使用我们的数据库类记录模拟结果
	SimulationDatabase simDb(dbFileName);
	simDb.InitializeDatabase();
	
	// 将runId字符串转换为整数，用于数据库记录
	uint32_t simulationRun = 1; // 默认为1
	if (!runId.empty()) {
		try {
			simulationRun = atoi(runId.c_str());
		} catch (const std::exception& e) {
			NS_LOG_INFO("无法将runId转换为整数: " << e.what());
		}
	}
	
	// 记录本次模拟结果（用于数据库记录）
	bool result = simDb.RecordSimulationResult(
		areaLength,
		areaWidth,
		areaHeight,
		numNodes,
		linkQuality,
		simulationRun,
		CompletionTime,
		sentPackets,
		receivedPackets,
		totalSent,
		totalReceived,
		overheadRatio,
		successRate
	);
	
	if (result) {
		NS_LOG_INFO("模拟结果已成功记录到数据库");
	} else {
		NS_LOG_INFO("模拟结果记录到数据库失败");
	}
	
	// ------------------------------------------------------------
	// ---------- 输出结果到本地data.db文件 -------------
	// ------------------------------------------------------------
	Ptr<DataOutputInterface> output = 0;
	output = CreateObject<SqliteDataOutput>();
	// 将收集到的数据写入文件
	if (output != 0)
		output->Output(dataCollector);
	// NS_LOG_INFO("数据已成功写入");
	// ------------- End -----------------



	// NS_LOG_INFO("-----------------仿真结束-------------------");
	Simulator::Destroy();
}

int main(int argc, char *argv[]) {
	CommandLine cmd;
	cmd.AddValue("numNodes", "节点个数", numNodes);
	cmd.AddValue("areaLength", "活动区域长度 (m)", areaLength);
	cmd.AddValue("areaWidth", "活动区域宽度 (m)", areaWidth);
	cmd.AddValue("areaHeight", "活动区域高度 (m)", areaHeight);
	cmd.AddValue("run", "运行标识", runId);
	std::string linkQuality = "medium";  // 默认中等链路质量
	cmd.AddValue("linkQuality", "Link quality (high/medium/low/very_poor)", linkQuality);
	cmd.AddValue("dbFileName", "数据库文件名", dbFileName);
	cmd.Parse(argc, argv);
	
	// 显式设置日志级别
	LogComponentEnable("wifi-adhoc-UAV-experiment", LOG_LEVEL_INFO);
	LogComponentEnable("wifi-adhoc-app", LOG_LEVEL_INFO);
	
	// 指定绝对路径（而不是使用~）
	const char* logDir = "/home/float/Desktop/ns-allinone-3.25/ns-3.25/scratch/EAGKA-Flooding/Log";
	struct stat st;
	if (stat(logDir, &st) != 0) {
		// 创建Log目录，权限为可读可写可执行
		mkdir(logDir, 0777);
		NS_LOG_INFO("创建日志目录: " << logDir);
	}
	
	// 生成日志文件名，使用ostringstream替代to_string
	std::ostringstream logFileNameStream;
	logFileNameStream << logDir << "/simulation_nodes" << numNodes 
		<< "_area" << (int)areaLength << "*" << (int)areaWidth << "*" << (int)areaHeight
		<< "_linkQuality" << linkQuality
		<< "_run" << runId << ".txt";
	std::string logFileName = logFileNameStream.str();
	
	// 重定向日志输出到文件
	std::ofstream logFile(logFileName.c_str());
	if (logFile.is_open()) {
		// 修改文件权限为可读可写
		chmod(logFileName.c_str(), 0666);
		
		// 保存原始的clog缓冲区（NS_LOG使用clog而不是cerr）
		std::streambuf* originalBuffer = std::clog.rdbuf();
		// 将clog重定向到文件
		std::clog.rdbuf(logFile.rdbuf());
		// 设置无缓冲，确保日志立即写入文件
		std::clog.setf(std::ios::unitbuf);
		
		// 添加明确的日志开始标记
		NS_LOG_INFO("=====================================");
		NS_LOG_INFO("实验开始: 节点数=" << numNodes << ", 活动区域长度=" << areaLength << ", 活动区域宽度=" << areaWidth << ", 活动区域高度=" << areaHeight << ", 运行标识=" << runId);
		NS_LOG_INFO("=====================================");
		
		// 标注实验节点数目
		input = numNodes;
		// 标注实验信息
		std::ostringstream ss;
		ss << "numNodes:" << numNodes << ";areaLength:" << areaLength << ";areaWidth:" << areaWidth << ";areaHeight:" << areaHeight;
		experiment = ss.str();
		ss.str("");
		strategy = "单轮通信";
		
		// 运行仿真
		startSimulation(linkQuality);
		
		// 确保所有日志都写入文件
		std::clog.flush();
		
		// 添加明确的日志结束标记
		NS_LOG_INFO("=====================================");
		NS_LOG_INFO("实验结束");
		NS_LOG_INFO("=====================================");
		
		// 恢复原始的输出
		std::clog.rdbuf(originalBuffer);
		logFile.close();
		
		std::cout << "日志已保存到: " << logFileName << std::endl;
	} else {
		NS_LOG_ERROR("无法创建日志文件: " << logFileName);
	}   
    return 0;
}
