/*
 * AdhocUdpApplication.cc
 *
 *  Created on: 2022年2月23日
 *      Author: float
 */
#include "AdhocUdpApplication.h"

#include <ostream>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <string>
#include <cstdlib> // for atoi
#include <cmath>


#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/stats-module.h"
#include "ns3/node.h"
#include "ns3/ptr.h"

using namespace ns3;


NS_LOG_COMPONENT_DEFINE("wifi-adhoc-app");


//------------------------------------------------------
//-- 发包应用实现
//------------------------------------------------------

// 获取类型ID
TypeId AppSender::GetTypeId(void) {
	static TypeId tid =
    // 设置父类为Application
			TypeId("AppSender").SetParent<Application>().AddConstructor<
					AppSender>().AddAttribute("PacketSize",	"The size of packets transmitted.", UintegerValue(96),
					MakeUintegerAccessor(&AppSender::m_pktSize),
					MakeUintegerChecker<uint32_t>(1)).AddAttribute("Destination", "Target host address.",
					Ipv4AddressValue("255.255.255.255"),
					MakeIpv4AddressAccessor(&AppSender::m_destAddr),
					MakeIpv4AddressChecker()).AddAttribute("Port","Destination app port.", UintegerValue(666),
					MakeUintegerAccessor(&AppSender::m_destPort),
					MakeUintegerChecker<uint32_t>()).AddAttribute("Interval",
					"Delay between transmissions.", UintegerValue(1),
					MakeUintegerAccessor(&AppSender::m_interval),
					MakeUintegerChecker<uint32_t>());
	return tid;
}

// 代码含义：
AppSender::AppSender() {
    m_sendCounter = 0;
    m_nodeId = 0;
    m_networkSize = 0;
    m_neighborList = new std::vector<Ipv4Address>();
    m_periodicInterval = 0.01; // 默认0.01秒间隔
}

// 析构函数
AppSender::~AppSender() {}

void AppSender::SetNodeId(uint32_t id) {
    m_nodeId = id;
}

void AppSender::SetNetworkSize(uint32_t size) {
    m_networkSize = size;
}

// 设置发包计数器
void AppSender::SetSendCounter(Ptr<CounterCalculator<> > calc) {
	m_sendCounter = 0;
}   


void AppSender::DoDispose(void) {
	m_Socket = 0;
    // m_neighborSocket = 0;
	// chain up
	Application::DoDispose();
}

// 启动应用
void AppSender::StartApplication() {
	
    // 创建UDP类型socket，并绑定
	TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
	m_Socket = Socket::CreateSocket(GetNode(), tid);       // 用于发送数据
    m_Socket->Bind();

	// 设置目的地址和端口
	InetSocketAddress dataRemote = InetSocketAddress(m_destAddr, m_destPort);
    // InetSocketAddress neighborRemote = InetSocketAddress(m_destAddr, m_neighborPort);
	
    // 设置广播
	m_Socket->SetAllowBroadcast(true);
    // m_neighborSocket->SetAllowBroadcast(true);
	
    // 初始化链接
	m_Socket->Connect(dataRemote);
    // m_neighborSocket->Connect(neighborRemote);

    // 第一次发送是广播，构建数据包，内容为节点ID
    std::ostringstream packetContent;
    packetContent << m_nodeId ;
    std::string content = packetContent.str();
    
    // 开始发送数据包 - 修改为使用广播发送，不需要指定具体邻居
    m_sendEvent = Simulator::Schedule(Seconds(0), &AppSender::SendPacket, this, m_destAddr, content);
    NS_LOG_INFO("节点" << m_nodeId << "开始发送数据包");

    // 1.2秒后开始周期性广播
    m_periodicEvent = Simulator::Schedule(Seconds(1.1), &AppSender::PeriodicBroadcast, this);
}

// 周期性广播当前密钥贡献
void AppSender::PeriodicBroadcast() {
    // 获取AppReceiver
    Ptr<AppReceiver> receiver = DynamicCast<AppReceiver>(GetNode()->GetApplication(1));
    // 如果已经收齐所有密钥贡献，则不再继续周期广播
    // if (receiver->IsCompleted()) {
    //     NS_LOG_INFO("节点" << m_nodeId << "已收齐所有密钥贡献");
    //     return;
    // }
    // 构建数据包，内容为自己的ID
    std::ostringstream packetContent;
    packetContent << m_nodeId;
    std::string content = packetContent.str();
    
    // NS_LOG_INFO("节点" << m_nodeId << "周期性广播密钥贡献: " << content);
    
    // 广播给所有节点
    SendPacket(m_destAddr, content);
    
    // 
    m_periodicEvent = Simulator::Schedule(Seconds(m_periodicInterval), &AppSender::PeriodicBroadcast, this);
}


void AppSender::StopApplication() {
	Simulator::Cancel(m_sendEvent);
    Simulator::Cancel(m_periodicEvent);

}


// 用于向选定的邻居发送数据包(目标地址，数据包内容)
void AppSender::SendPacket(Ipv4Address neighborAddress, std::string packetContent) {
    std::ostringstream msg;
    // 数据包内容    
    msg << packetContent;
    // 创建数据包
    std::string content = msg.str();
    Ptr<Packet> packet = Create<Packet>((uint8_t*) content.c_str(), content.size());
    // 发送数据包
    InetSocketAddress remote = InetSocketAddress(neighborAddress, m_destPort);
    m_Socket->Connect(remote);
    m_Socket->Send(packet);
    // 记录日志
    // NS_LOG_INFO("节点" << m_nodeId << "发送数据包" << "给" << neighborAddress);
    // NS_LOG_INFO("节点" << m_nodeId << "发送数据包" << content << "给" << neighborAddress);
    // 发送数据包数+1
    m_sendCounter++;
}


//------------------------------------------------------
//-- 收包应用实现
//------------------------------------------------------
TypeId AppReceiver::GetTypeId(void) {
	static TypeId tid =
			TypeId("AppReceiver").SetParent<Application>().AddConstructor<
					AppReceiver>()
					.AddAttribute("Port", "Listening port.", UintegerValue(666),
							MakeUintegerAccessor(&AppReceiver::m_port),
							MakeUintegerChecker<uint32_t>())
					.AddAttribute("Destination", "Target host address.",
							Ipv4AddressValue("255.255.255.255"),
							MakeIpv4AddressAccessor(&AppReceiver::m_destAddr),
							MakeIpv4AddressChecker());
	return tid;
}

AppReceiver::AppReceiver() {
    m_contributionBuffer = new std::map<std::string, int>;
    m_receivedCounter = 0;   
    m_isCompleted = false;
    m_nodeId = 0;
    m_networkSize = 0;
    m_neighborList = new std::vector<Ipv4Address>();
    m_ReceivedContributionNumber = 0;
}

AppReceiver::~AppReceiver() {
    delete m_contributionBuffer;
}

// 设置节点数量
void AppReceiver::SetNumNodes(uint32_t num) {
	m_numNodes = num;
}

// 设置节点ID
void AppReceiver::SetNodeId(uint32_t id) {
	m_nodeId = id;
}

// 设置网络大小
void AppReceiver::SetNetworkSize(uint32_t size) {
    m_networkSize = size;
}

// 设置收包计数器
void AppReceiver::SetReceiveCounter(Ptr<CounterCalculator<> > calc){
    m_receivedCounter = 0;
}


// 获取收包计数器
uint32_t AppReceiver::GetReceivedPackets() const {
    return m_receivedCounter;
}

// 判断是否完成
bool AppReceiver::IsCompleted() const {
    return m_isCompleted;
}


// 用于释放资源
void AppReceiver::DoDispose(void) {
	m_socket = 0;
    // m_neighborSocket = 0;    
	// chain up
	Application::DoDispose();
}

// 更新邻居列表，只保留最新的N/2个邻居,N为节点数量
void AppReceiver::UpdateNeighborList(Ipv4Address neighborAddress) {
    // 如果该邻居在邻居列表中，则不添加
    if (std::find(m_neighborList->begin(), m_neighborList->end(), neighborAddress) != m_neighborList->end()) {
        // 将该邻居在邻居列表中的位置，移动到列表的末尾
        m_neighborList->erase(std::find(m_neighborList->begin(), m_neighborList->end(), neighborAddress));
        m_neighborList->push_back(neighborAddress);
    } else {
        // 否则添加邻居，只保留最新的N/2个邻居
        m_neighborList->push_back(neighborAddress);
        if (m_neighborList->size() > m_networkSize / 2) {
            m_neighborList->erase(m_neighborList->begin());
        }
    }
}

// 启动应用
void AppReceiver::StartApplication() {
	TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
	m_socket = Socket::CreateSocket(GetNode(), tid);
    
    // 获取节点IP地址
    Ipv4Address address = GetNode()->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal();
    // 绑定IP地址和端口
    InetSocketAddress local = InetSocketAddress(address, m_port);
	m_socket->Bind(local);
    NS_LOG_INFO("节点" << m_nodeId << "开始监听: " << address << ":" << m_port);
	// 设置回调（干啥的？）
    m_socket->SetRecvCallback(MakeCallback(&AppReceiver::Receive, this));
}

void AppReceiver::StopApplication() {
	if (m_socket != 0) {
		m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> >());
	}
}

void AppReceiver::Receive(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from))) {
        m_receivedCounter++;
        // 获取发送方地址
        Ipv4Address senderAddr = InetSocketAddress::ConvertFrom(from).GetIpv4();
        // 将发送方地址添加到邻居列表
        UpdateNeighborList(senderAddr);
        // 节点收到来自XX邻居的消息包
        // NS_LOG_INFO("节点" << m_nodeId << "收到来自" << senderAddr << "的消息包");
               
        // 从packet中提取数据
        uint8_t *buffer = new uint8_t[packet->GetSize()];
        packet->CopyData(buffer, packet->GetSize());
        std::string msg = std::string((char*)buffer, packet->GetSize());
        delete[] buffer;

        
        // 从msg中提取发送节点ID,密钥贡献ID就是msg,使用string流替代std::stoi
        uint32_t keyContributionId = atoi(msg.c_str());
        // NS_LOG_INFO("节点" << m_nodeId << "收到来自" << senderAddr << "的消息包，内容为" << msg);
        
        // 如果不是自己的贡献，或者自己还没收齐密钥贡献，则转发
        if (keyContributionId != m_nodeId || m_ReceivedContributionNumber < m_networkSize-1) {
        // if (keyContributionId != m_nodeId) {
            // 如果本地没有收到过，buffer中没有
            if (m_contributionBuffer->count(msg) == 0) {
                NS_LOG_INFO("节点" << m_nodeId << "收到" << msg << "，本地没有收到过");
                // 设为1，表示收到
                m_contributionBuffer->insert(std::make_pair(msg, 1));
                // 收到的贡献+1
                m_ReceivedContributionNumber++;
                // 如果收到所有节点的贡献，则完成
            } 
            if (m_ReceivedContributionNumber == m_networkSize-1) {
                    m_isCompleted = true;
                }
            // 构建数据包内容
            std::ostringstream msg;
            // 数据包内容    
            msg << keyContributionId;
            std::string content = msg.str();
            // 遍历发给所有邻居，除了原数据包的发送方
            for (uint32_t i = 0; i < m_neighborList->size(); i++) {     
                // 获取邻居的IP地址
                Ipv4Address neighborAddr = m_neighborList->at(i);
                // 如果邻居不是原数据包的发送方，则转发
                if (neighborAddr != senderAddr) {
                    Ptr<AppSender> sender = DynamicCast<AppSender>(GetNode()->GetApplication(0));
                    sender->SendPacket(neighborAddr, content);
                    // 记录日志
                    // NS_LOG_INFO("节点" << m_nodeId << "转发数据包" << content << "给" << neighborAddr);
                }
            }     
        }
    }
}












