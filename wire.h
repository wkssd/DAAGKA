#ifndef IOT_RAFT_WIRE_H
#define IOT_RAFT_WIRE_H

#include "raft.h"
#include <utility>

namespace iotraft {
namespace wire {

typedef std::vector<uint8_t> Bytes;
static const size_t MaxMessage = 262144;
static const size_t FragmentPayload = 1000;
static const size_t FragmentHeader = 28;

inline void put(Bytes& b, uint64_t v, unsigned n) {
  for (unsigned i = n; i > 0; --i) b.push_back(static_cast<uint8_t>(v >> ((i - 1) * 8)));
}
struct Reader {
  const Bytes& b;
  size_t p;
  explicit Reader(const Bytes& bytes) : b(bytes), p(0) {}
  uint64_t get(unsigned n) {
    if (n > b.size() - p) throw std::invalid_argument("truncated wire data");
    uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v = (v << 8) | b[p++];
    return v;
  }
  std::string text() {
    const uint64_t n = get(4);
    if (n > b.size() - p) throw std::invalid_argument("truncated string");
    std::string s(b.begin() + p, b.begin() + p + static_cast<size_t>(n));
    p += static_cast<size_t>(n);
    return s;
  }
};
inline void text(Bytes& b, const std::string& s) {
  if (s.size() > MaxMessage || b.size() + 4 + s.size() > MaxMessage)
    throw std::invalid_argument("wire message too large");
  put(b, s.size(), 4);
  b.insert(b.end(), s.begin(), s.end());
}
inline Bytes encode(const Message& m) {
  if (static_cast<unsigned>(m.kind) > 3 || m.entries.size() > 16)
    throw std::invalid_argument("invalid raft message");
  Bytes b;
  put(b, 0x52414654, 4); put(b, 1, 1); put(b, static_cast<unsigned>(m.kind), 1);
  put(b, m.accepted ? 1 : 0, 1); put(b, 0, 1);
  put(b, m.from, 4); put(b, m.to, 4);
  put(b, m.term, 8); put(b, m.lastTerm, 8); put(b, m.prev, 8);
  put(b, m.commit, 8); put(b, m.matched, 8); put(b, m.sequence, 8);
  put(b, m.entries.size(), 4);
  for (size_t i = 0; i < m.entries.size(); ++i) {
    put(b, m.entries[i].term, 8);
    text(b, m.entries[i].request); text(b, m.entries[i].value);
  }
  return b;
}
inline bool decode(const Bytes& b, Message& result) {
  if (b.size() > MaxMessage) return false;
  try {
    Reader r(b);
    if (r.get(4) != 0x52414654 || r.get(1) != 1) return false;
    const unsigned kind = static_cast<unsigned>(r.get(1));
    const unsigned accepted = static_cast<unsigned>(r.get(1));
    if (kind > 3 || accepted > 1 || r.get(1) != 0) return false;
    Message m;
    m.kind = static_cast<Kind>(kind); m.accepted = accepted != 0;
    m.from = static_cast<NodeId>(r.get(4)); m.to = static_cast<NodeId>(r.get(4));
    m.term = r.get(8); m.lastTerm = r.get(8); m.prev = r.get(8);
    m.commit = r.get(8); m.matched = r.get(8); m.sequence = r.get(8);
    const uint64_t count = r.get(4);
    if (count > 16) return false;
    for (uint64_t i = 0; i < count; ++i) {
      Entry e; e.term = r.get(8); e.request = r.text(); e.value = r.text();
      m.entries.push_back(e);
    }
    if (r.p != b.size()) return false;
    result = m;
    return true;
  } catch (const std::invalid_argument&) { return false; }
}

// Transport IDs are per source and must not be reused in a run. The source is
// authenticated by the adapter against the UDP endpoint, not trusted from bytes.
inline std::vector<Bytes> fragment(const Bytes& bytes, NodeId source, uint64_t id) {
  if (bytes.empty() || bytes.size() > MaxMessage || !id)
    throw std::invalid_argument("invalid fragmentation input");
  std::vector<Bytes> out;
  const size_t count = (bytes.size() + FragmentPayload - 1) / FragmentPayload;
  for (size_t i = 0; i < count; ++i) {
    Bytes b;
    put(b, 0x52465247, 4); put(b, 1, 1); put(b, 0, 1); put(b, 0, 2);
    put(b, source, 4); put(b, id, 8); put(b, bytes.size(), 4);
    put(b, i, 2); put(b, count, 2);
    const size_t begin = i * FragmentPayload;
    const size_t end = std::min(bytes.size(), begin + FragmentPayload);
    b.insert(b.end(), bytes.begin() + begin, bytes.begin() + end);
    out.push_back(b);
  }
  return out;
}

class Reassembler {
 public:
  enum Result { Rejected, Pending, Duplicate, Complete };
  explicit Reassembler(size_t slots = 128, size_t budget = 4 * 1024 * 1024,
                       uint64_t timeoutMs = 500, size_t tombstones = 4096)
      : slots_(slots), budget_(budget), timeout_(timeoutMs), tombstones_(tombstones),
        allocated_(0), now_(0), expired_(0) {
    if (!slots || !budget || !timeoutMs || !tombstones)
      throw std::invalid_argument("invalid reassembly bounds");
  }
  void expire(uint64_t now) {
    if (now < now_) throw std::invalid_argument("nonmonotonic reassembly clock");
    now_ = now;
    for (std::map<Key, Assembly>::iterator i = active_.begin(); i != active_.end();) {
      if (now - i->second.start >= timeout_) {
        allocated_ -= i->second.data.size(); active_.erase(i++); ++expired_;
      } else ++i;
    }
    for (std::map<Key, uint64_t>::iterator i = done_.begin(); i != done_.end();) {
      if (now - i->second >= timeout_) done_.erase(i++); else ++i;
    }
  }
  Result accept(NodeId endpointSource, const Bytes& datagram, uint64_t now, Bytes& out) {
    expire(now);
    out.clear();
    if (datagram.size() < FragmentHeader || datagram.size() > FragmentHeader + FragmentPayload)
      return Rejected;
    Reader r(datagram);
    if (r.get(4) != 0x52465247 || r.get(1) != 1 || r.get(1) || r.get(2)) return Rejected;
    const NodeId source = static_cast<NodeId>(r.get(4));
    const uint64_t id = r.get(8);
    const size_t total = static_cast<size_t>(r.get(4));
    const size_t index = static_cast<size_t>(r.get(2));
    const size_t count = static_cast<size_t>(r.get(2));
    if (source != endpointSource || !id || !total || total > MaxMessage ||
        count != (total + FragmentPayload - 1) / FragmentPayload || index >= count)
      return Rejected;
    const size_t offset = index * FragmentPayload;
    const size_t length = std::min(FragmentPayload, total - offset);
    if (datagram.size() != FragmentHeader + length) return Rejected;
    const Key key(source, id);
    if (done_.count(key)) return Duplicate;
    std::map<Key, Assembly>::iterator found = active_.find(key);
    if (found == active_.end()) {
      // Reserve one completion tombstone per admitted assembly. Never evict
      // completed IDs early merely to admit fresh traffic.
      if (active_.size() >= slots_ || total > budget_ - allocated_ ||
          done_.size() + active_.size() >= tombstones_) return Rejected;
      Assembly a; a.start = now; a.received = 0;
      a.data.resize(total); a.seen.resize(count, false);
      found = active_.insert(std::make_pair(key, a)).first;
      allocated_ += total;
    }
    Assembly& a = found->second;
    if (a.data.size() != total || a.seen.size() != count) return Rejected;
    if (a.seen[index]) {
      return std::equal(datagram.begin() + FragmentHeader, datagram.end(),
                        a.data.begin() + offset) ? Duplicate : Rejected;
    }
    std::copy(datagram.begin() + FragmentHeader, datagram.end(), a.data.begin() + offset);
    a.seen[index] = true; ++a.received;
    if (a.received != count) return Pending;
    allocated_ -= a.data.size(); out.swap(a.data);
    active_.erase(found); done_[key] = now;
    return Complete;
  }
  size_t pending() const { return active_.size(); }
  size_t allocated() const { return allocated_; }
  uint64_t expired() const { return expired_; }
 private:
  typedef std::pair<NodeId, uint64_t> Key;
  struct Assembly { uint64_t start; size_t received; Bytes data; std::vector<bool> seen; };
  size_t slots_, budget_;
  uint64_t timeout_;
  size_t tombstones_, allocated_;
  uint64_t now_, expired_;
  std::map<Key, Assembly> active_;
  std::map<Key, uint64_t> done_;
};

} // namespace wire
} // namespace iotraft
#endif
