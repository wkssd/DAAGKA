#include "append-pacer.h"
#include <iostream>
#include <stdexcept>
using namespace iotraft;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (0)
int main() {
  try {
    AppendPacer p(2, 6);
    Message a; a.kind = Kind::Append; a.from = 0; a.to = 1; a.term = 1; a.sequence = 1;
    Message b = a; b.to = 2; b.sequence = 2;
    wire::Bytes body(3, 42), different(3, 43);
    CHECK(p.enqueue(a, body) == AppendPacer::Queued);
    CHECK(p.enqueue(a, body) == AppendPacer::Coalesced);
    bool rejected = false;
    try { p.enqueue(a, different); } catch (const std::invalid_argument&) { rejected = true; }
    CHECK(rejected && p.size() == 1 && p.allocated() == 3);
    CHECK(p.enqueue(b, body) == AppendPacer::Queued);
    Message c = a; c.to = 3;
    CHECK(p.enqueue(c, body) == AppendPacer::Full);
    AppendPacer::Item item;
    CHECK(p.pop(10, 100, item) && item.message.sequence == 1 && item.body == body);
    CHECK(!p.pop(109, 100, item));
    CHECK(p.pop(110, 100, item) && item.message.sequence == 2);
    CHECK(p.allocated() == 0 && p.size() == 0);
    CHECK(p.enqueue(a, wire::Bytes(7, 0)) == AppendPacer::Full);
    CHECK(p.enqueue(a, body) == AppendPacer::Queued);
    CHECK(p.prune([](const Message&) { return false; }) == 1);
    CHECK(p.allocated() == 0 && !p.pop(1000, 100, item));
    const std::vector<NodeId> ids = {0, 1, 2};
    Raft r(0, ids, 150, 30); r.setRetryPolicy(100, 400); r.tick(150); r.drain();
    Message vote; vote.kind = Kind::VoteReply; vote.from = 1; vote.to = 0; vote.term = 1; vote.accepted = true;
    r.receive(vote); auto out = r.drain(); a = out.front();
    CHECK(r.isPending(a));
    CHECK(p.enqueue(a, body) == AppendPacer::Queued);
    Message ack; ack.kind = Kind::AppendReply; ack.from = a.to; ack.to = 0;
    ack.term = a.term; ack.sequence = a.sequence; ack.accepted = true; ack.matched = 1;
    r.receive(ack); CHECK(!r.isPending(a));
    CHECK(p.prune([&](const Message& m) { return r.isPending(m); }) == 1);
    b = out.back(); CHECK(r.isPending(b)); CHECK(p.enqueue(b, body) == AppendPacer::Queued);
    Message higher; higher.kind = Kind::Append; higher.from = 1; higher.to = 0; higher.term = 2;
    r.receive(higher); CHECK(!r.isPending(b));
    CHECK(p.prune([&](const Message& m) { return r.isPending(m); }) == 1);
    CHECK(p.allocated() == 0);
    std::cout << "PASS FIFO, exact gap, immutable identity, coalescing, byte/slot bounds, ACK and term cleanup\n";
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
