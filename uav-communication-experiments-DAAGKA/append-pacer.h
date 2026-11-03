#ifndef IOT_APPEND_PACER_H
#define IOT_APPEND_PACER_H
#include "wire.h"
#include <deque>

namespace iotraft {
// One queued immutable RPC per destination, with global slots and byte bounds.
class AppendPacer {
 public:
  struct Item { Message message; wire::Bytes body; };
  enum Result { Queued, Coalesced, Full };
  explicit AppendPacer(size_t slots = 50, size_t bytes = 4 * 1024 * 1024)
      : slots_(slots), budget_(bytes), allocated_(0), due_(0) {}
  Result enqueue(const Message& message, const wire::Bytes& body) {
    for (const auto& item : queue_) {
      if (item.message.to != message.to) continue;
      if (item.message.term == message.term && item.message.sequence == message.sequence) {
        if (item.body != body) throw std::invalid_argument("RPC identity changed content");
        return Coalesced;
      }
      return Full;
    }
    if (queue_.size() >= slots_ || body.size() > budget_ - allocated_) return Full;
    queue_.push_back(Item{message, body}); allocated_ += body.size(); return Queued;
  }
  template<class Valid> size_t prune(Valid valid) {
    size_t removed = 0;
    for (auto i = queue_.begin(); i != queue_.end();) {
      if (!valid(i->message)) { allocated_ -= i->body.size(); i = queue_.erase(i); ++removed; }
      else ++i;
    }
    return removed;
  }
  bool pop(uint64_t now, uint64_t gap, Item& item) {
    if (queue_.empty() || now < due_) return false;
    item = queue_.front(); queue_.pop_front(); allocated_ -= item.body.size();
    due_ = now + gap; return true;
  }
  size_t size() const { return queue_.size(); }
  size_t allocated() const { return allocated_; }
 private:
  size_t slots_, budget_, allocated_;
  uint64_t due_;
  std::deque<Item> queue_;
};
}
#endif
