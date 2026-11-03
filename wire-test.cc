#include "wire.h"
#include <iostream>
#include <stdexcept>

using namespace iotraft;
using namespace iotraft::wire;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string("failed: ") + #x); } while (0)

int main() {
  try {
    Message m; m.kind = Kind::Append; m.from = 0x01020304; m.to = 49;
    m.term = UINT64_C(0x0102030405060708); m.lastTerm = 9; m.prev = 12;
    m.commit = 11; m.matched = 10; m.sequence = 1234; m.accepted = true;
    m.entries.push_back(Entry(6, "gka-1", std::string(10384, '\xAB')));
    const Bytes encoded = encode(m);
    CHECK(encoded[8] == 1 && encoded[9] == 2 && encoded[10] == 3 && encoded[11] == 4);
    CHECK(encoded[16] == 1 && encoded[23] == 8);
    Message decoded;
    CHECK(decode(encoded, decoded)); CHECK(encode(decoded) == encoded);
    CHECK(decoded.entries[0].value.size() == 10384);
    for (size_t i = 0; i < encoded.size(); ++i) {
      Bytes truncated(encoded.begin(), encoded.begin() + i);
      CHECK(!decode(truncated, decoded));
    }
    Bytes bad = encoded; bad.push_back(0); CHECK(!decode(bad, decoded));
    bad = encoded; bad[5] = 4; CHECK(!decode(bad, decoded));
    bad = encoded; bad[6] = 2; CHECK(!decode(bad, decoded));
    bad = encoded; bad[64] = 255; CHECK(!decode(bad, decoded));
    std::cout << "PASS codec fixed-endian roundtrip and " << encoded.size()
              << " truncation boundaries\n";

    Bytes out;
    Reassembler small;
    const std::vector<Bytes> one = fragment(encode(Message()), 0, 1);
    CHECK(one.size() == 1);
    CHECK(small.accept(0, one[0], 0, out) == Reassembler::Complete);
    CHECK(out == encode(Message()));
    CHECK(small.accept(0, one[0], 1, out) == Reassembler::Duplicate);
    CHECK(out.empty());
    std::cout << "PASS small packet and completed duplicate suppression\n";

    Bytes material(10384);
    for (size_t i = 0; i < material.size(); ++i) material[i] = static_cast<uint8_t>(i);
    const std::vector<Bytes> parts = fragment(material, 7, 22);
    CHECK(parts.size() == 11);
    Reassembler reverse;
    for (size_t i = parts.size(); i > 0; --i) {
      CHECK(reverse.accept(7, parts[i - 1], 0, out) ==
            (i == 1 ? Reassembler::Complete : Reassembler::Pending));
      if (i == 1) CHECK(out == material);
      CHECK(reverse.accept(7, parts[i - 1], 0, out) == Reassembler::Duplicate);
    }
    CHECK(reverse.allocated() == 0 && reverse.pending() == 0);
    std::cout << "PASS 10384 bytes / 11 fragments, reverse order and duplicates\n";

    Reassembler missing(2, 30000, 50);
    for (size_t i = 0; i + 1 < parts.size(); ++i)
      CHECK(missing.accept(7, parts[i], i, out) == Reassembler::Pending);
    CHECK(missing.pending() == 1 && missing.allocated() == 10384);
    missing.expire(49); CHECK(missing.pending() == 1);
    missing.expire(50); CHECK(missing.pending() == 0 && missing.allocated() == 0);
    CHECK(missing.expired() == 1);
    CHECK(missing.accept(7, parts.back(), 51, out) == Reassembler::Pending);
    missing.expire(101); CHECK(missing.expired() == 2);
    std::cout << "PASS missing fragment timeout and exact resource release\n";

    Reassembler bounds(1, 10384, 50, 2);
    CHECK(bounds.accept(7, parts[0], 0, out) == Reassembler::Pending);
    const std::vector<Bytes> other = fragment(material, 7, 23);
    CHECK(bounds.accept(7, other[0], 1, out) == Reassembler::Rejected);
    CHECK(bounds.accept(8, parts[1], 1, out) == Reassembler::Rejected);
    bad = parts[0]; bad.back() ^= 1;
    CHECK(bounds.accept(7, bad, 1, out) == Reassembler::Rejected);
    bad = parts[1]; bad.pop_back();
    CHECK(bounds.accept(7, bad, 1, out) == Reassembler::Rejected);
    for (size_t i = 0; i < FragmentHeader; ++i) {
      bad.assign(parts[0].begin(), parts[0].begin() + i);
      CHECK(bounds.accept(7, bad, 1, out) == Reassembler::Rejected);
    }
    bad = parts[1]; bad[24] = 255;
    CHECK(bounds.accept(7, bad, 1, out) == Reassembler::Rejected);
    CHECK(bounds.allocated() == 10384 && bounds.pending() == 1);
    bounds.expire(50);
    CHECK(bounds.accept(7, other[0], 50, out) == Reassembler::Pending);
    Reassembler tiny(1, 10383, 50);
    CHECK(tiny.accept(7, parts[0], 0, out) == Reassembler::Rejected);
    Reassembler tomb(2, 30000, 50, 1);
    CHECK(tomb.accept(0, one[0], 0, out) == Reassembler::Complete);
    CHECK(tomb.accept(7, parts[0], 1, out) == Reassembler::Rejected);
    CHECK(tomb.accept(7, parts[0], 50, out) == Reassembler::Pending);
    std::cout << "PASS slot/byte/tombstone bounds, malformed and conflicting fragments\n";
    std::cout << "ALL WIRE TESTS PASSED\n";
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n'; return 1;
  }
}
