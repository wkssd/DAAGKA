/*
 * AdhocUdpApplication.h
 *
 *  Created on: 2022年2月23日
 *      Author: float
 */

#ifndef ADHOC_UDP_APPLICATION_H_
#define ADHOC_UDP_APPLICATION_H_


#include "ns3/core-module.h"
#include "ns3/application.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/stats-module.h"
#include <map>
#include <string>
#include <fstream>
#include <vector>
#include <set>

using namespace ns3;

/**
 * 发包应用
 */
class AppSender: public Application {
public:
	static TypeId GetTypeId(void);
	AppSender();
	virtual ~AppSender();
	void SetSendCounter(Ptr<CounterCalculator<> > sendCounter); // 设置发包计数器，Ptr<CounterCalculator<> > 是一个智能指针，指向一个CounterCalculator对象
	void SetNodeId(uint32_t id); // 设置节点ID
	void SetNetworkSize(uint32_t size); // 设置网络大小
	void AddNeighbor(Ipv4Address neighbor); // 添加邻居
	void UpdateNeighborList(Ipv4Address neighborAddress); // 更新邻居列表
	void SendPacket(Ipv4Address neighborAddress, std::string packetContent); // 向指定邻居发送数据包
	
	// 获取发送的数据包数量
	uint32_t GetSentPackets() const { return m_sendCounter; }
	// 获取邻居列表
	std::vector<Ipv4Address>* GetNeighborList() { return m_neighborList; }

	// 设置周期性广播间隔（秒）
	void SetPeriodicBroadcastInterval(double interval) { m_periodicInterval = interval; }

	// 周期性广播当前密钥贡献
	void PeriodicBroadcast();

protected:
	virtual void DoDispose(void);

private:
	virtual void StartApplication(void);
	virtual void StopApplication(void);

	uint32_t m_pktSize;		// 包大小
	Ipv4Address m_destAddr;	// 目的地址
	uint16_t m_destPort;		// 目的端口
	uint32_t m_interval;       // 发送间隔

	Ptr<Socket> m_Socket; 	// 用于发送数据
	EventId m_sendEvent;			// 发送事件
	EventId m_periodicEvent;     // 周期性发送事件

	uint32_t m_sendCounter;		// 发包计数器
	uint32_t m_nodeId;			// 节点ID
	std::vector<Ipv4Address>* m_neighborList;	// 邻居列表
	uint32_t m_networkSize;		// 网络大小
	double m_periodicInterval; // 周期性广播间隔
};

// -------------------------------------------------------------------

/**
 * 收包应用
 */
class AppReceiver: public Application {
public:
	static TypeId GetTypeId(void);
	AppReceiver();
	virtual ~AppReceiver();
	void SetReceiveCounter(Ptr<CounterCalculator<> > calc); // 设置收包计数器
	void SetNumNodes(uint32_t num);
	void SetNodeId(uint32_t id);
	void SetNetworkSize(uint32_t size);
	// void SetReceivedPackets(uint32_t receivedPackets); // 设置接收到的数据包数量
	uint32_t GetReceivedPackets() const; // 获取接收到的数据包数量
	bool IsCompleted() const; // 是否收齐所有节点的包

	// 辅助方法：生成随机数
	double GetRandomValue();
	// 辅助方法：将数字转换为字符串
	std::string ToString(uint32_t value);
	
	// 辅助方法：将std::vector<bool> forwardingContributions格式的密钥贡献集合转换为01字符串
	std::string ContributionsToString(const std::vector<bool>& contributions) const;

	// 辅助方法：更新邻居列表
	void UpdateNeighborList(Ipv4Address neighborAddress);

protected:
	virtual void DoDispose(void);

private:
	virtual void StartApplication(void);
	virtual void StopApplication(void);

	void Receive(Ptr<Socket> socket);

	Ptr<Socket> m_socket; // 用于接收数据
	Ipv4Address m_destAddr;

	uint16_t m_port; // 数据通信端口

	// 收包计数器
	Ptr<CounterCalculator<> > receivedCounter;
	// 网络总节点数
	uint32_t m_numNodes;
	// 网络节点ID
	uint32_t m_nodeId;
	// 是否收齐所有节点的包
	bool m_isCompleted;
	// 网络大小
	uint32_t m_networkSize;

	// 收包计数器
	uint32_t m_receivedCounter;
	// 邻居列表
	std::vector<Ipv4Address>* m_neighborList;
	// 数据包缓冲区
	std::map<std::string, int>* m_contributionBuffer;
	// 收到贡献数量
	uint32_t m_ReceivedContributionNumber;
};


#endif /* ADHOC_UDP_APPLICATION_H_ */
