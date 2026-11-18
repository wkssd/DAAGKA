#ifndef IOT_NS3_FAULT_H
#define IOT_NS3_FAULT_H
#include "../raft-core/raft.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/mobility-model.h"
#include "ns3/node.h"
class IsolationLossModel : public ns3::PropagationLossModel {
 public:
  static ns3::TypeId GetTypeId() {
    static ns3::TypeId tid=ns3::TypeId("ns3::IoTIsolationLossModel")
      .SetParent<ns3::PropagationLossModel>().AddConstructor<IsolationLossModel>();
    return tid;
  }
  void SetIsolated(const std::set<iotraft::NodeId>& ids) { isolated_=ids; }
 private:
  double DoCalcRxPower(double power,ns3::Ptr<ns3::MobilityModel> a,
                       ns3::Ptr<ns3::MobilityModel> b) const override {
    const auto source=a->GetObject<ns3::Node>(),target=b->GetObject<ns3::Node>();
    if(!source || !target) throw std::invalid_argument("fault endpoint has no Node");
    return isolated_.count(source->GetId()) || isolated_.count(target->GetId()) ? -1000000.0 : power;
  }
  int64_t DoAssignStreams(int64_t) override {return 0;}
  std::set<iotraft::NodeId> isolated_;
};
NS_OBJECT_ENSURE_REGISTERED(IsolationLossModel);
#endif
