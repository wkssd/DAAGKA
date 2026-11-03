#include "raft.h"
#include <deque>
#include <iostream>
#include <memory>
#include <stdexcept>

using namespace iotraft;
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string("failed: ") + #x); } while (0)

struct Cluster {
  std::vector<std::unique_ptr<Raft> > nodes;
  std::set<NodeId> isolated;
  std::deque<Message> queue;
  uint64_t now;
  explicit Cluster(unsigned n) : now(0) {
    std::vector<NodeId> ids;
    for (unsigned i = 0; i < n; ++i) ids.push_back(i);
    for (unsigned i = 0; i < n; ++i)
      nodes.push_back(std::unique_ptr<Raft>(new Raft(i, ids, 150 + i * 37)));
  }
  void collect() {
    for (size_t i = 0; i < nodes.size(); ++i) {
      std::vector<Message> out = nodes[i]->drain();
      for (size_t j = 0; j < out.size(); ++j) queue.push_back(out[j]);
    }
  }
  void flush(bool duplicate = false) {
    collect();
    size_t budget = 100000;
    while (!queue.empty()) {
      CHECK(budget--);
      Message m = queue.front(); queue.pop_front();
      if (!isolated.count(m.from) && !isolated.count(m.to)) {
        nodes[m.to]->receive(m);
        if (duplicate) nodes[m.to]->receive(m);
      }
      collect();
    }
    invariants();
  }
  void run(uint64_t ms, bool duplicate = false) {
    const uint64_t end = now + ms;
    while (now < end) {
      ++now;
      for (size_t i = 0; i < nodes.size(); ++i) nodes[i]->tick(now);
      flush(duplicate);
    }
  }
  NodeId leader() {
    for (size_t i = 0; i < nodes.size(); ++i)
      if (!isolated.count(i) && nodes[i]->role() == Role::Leader) return i;
    throw std::runtime_error("no leader");
  }
  void invariants() {
    for (size_t i = 0; i < nodes.size(); ++i) {
      CHECK(nodes[i]->applied() == nodes[i]->committed());
      CHECK(nodes[i]->committed() <= nodes[i]->lastIndex());
      for (size_t j = i + 1; j < nodes.size(); ++j) {
        if (nodes[i]->role() == Role::Leader && nodes[j]->role() == Role::Leader)
          CHECK(nodes[i]->term() != nodes[j]->term());
        Index end = std::min(nodes[i]->committed(), nodes[j]->committed());
        for (Index k = 1; k <= end; ++k) {
          CHECK(nodes[i]->log()[k].term == nodes[j]->log()[k].term);
          CHECK(nodes[i]->log()[k].request == nodes[j]->log()[k].request);
          CHECK(nodes[i]->log()[k].value == nodes[j]->log()[k].value);
        }
      }
    }
  }
};

void basic(unsigned n) {
  Cluster c(n); c.run(500);
  NodeId leader = c.leader();
  CHECK(c.nodes[leader]->propose("single-gka", "material"));
  c.flush(true); c.run(100, true);
  for (unsigned i = 0; i < n; ++i) {
    CHECK(c.nodes[i]->state().at("single-gka") == "material");
    CHECK(c.nodes[i]->applicationCount() == 1);
  }
  Index before = c.nodes[leader]->lastIndex();
  CHECK(c.nodes[leader]->propose("single-gka", "material"));
  CHECK(!c.nodes[leader]->propose("single-gka", "different"));
  CHECK(c.nodes[leader]->lastIndex() == before);
}

void partition() {
  Cluster c(5); c.run(500);
  NodeId old = c.leader();
  c.isolated.insert(old);
  Index committed = c.nodes[old]->committed();
  CHECK(c.nodes[old]->propose("discard", "uncommitted"));
  c.flush(); c.run(600);
  CHECK(c.nodes[old]->committed() == committed);
  NodeId next = c.leader(); CHECK(next != old);
  CHECK(c.nodes[next]->propose("retained", "committed"));
  c.flush(); c.run(100);
  c.isolated.clear(); c.run(500);
  CHECK(c.nodes[old]->role() == Role::Follower);
  for (size_t i = 0; i < c.nodes.size(); ++i) {
    CHECK(c.nodes[i]->state().count("discard") == 0);
    CHECK(c.nodes[i]->state().at("retained") == "committed");
  }
}

void minority(bool bounded = false) {
  Cluster c(5);
  if (bounded) for (auto& node : c.nodes) node->setRetryPolicy(100, 400);
  c.run(500);
  NodeId leader = c.leader();
  for (NodeId i = 0; i < 5; ++i) if (i != leader && c.isolated.size() < 3) c.isolated.insert(i);
  Index before = c.nodes[leader]->committed();
  CHECK(c.nodes[leader]->propose("minority", "pending"));
  c.flush(); c.run(100);
  CHECK(c.nodes[leader]->committed() == before);
  c.isolated.clear(); c.run(bounded ? 500 : 100);
  CHECK(c.nodes[leader]->state().count("minority") == 1);
}

void currentTermAndIdempotence() {
  const std::vector<NodeId> ids = {0, 1, 2};
  Raft r(0, ids, 150);
  Message a; a.kind = Kind::Append; a.from = 1; a.to = 0; a.term = 1;
  for (unsigned i = 0; i < 17; ++i) a.entries.push_back(Entry(1, "same", "value"));
  r.receive(a); r.drain();
  r.tick(150); r.drain();
  Message vote; vote.kind = Kind::VoteReply; vote.from = 2; vote.to = 0;
  vote.term = r.term(); vote.accepted = true; r.receive(vote);
  CHECK(r.role() == Role::Leader);
  const Index inheritedEnd = r.lastIndex();
  CHECK(r.propose("same", "value"));
  CHECK(!r.propose("same", "conflicting"));
  CHECK(r.lastIndex() == inheritedEnd);
  CHECK(r.state().empty());
  std::vector<Message> out = r.drain();
  Message sent;
  for (size_t i = 0; i < out.size(); ++i) if (out[i].to == 2) sent = out[i];
  Message ack; ack.kind = Kind::AppendReply; ack.from = 2; ack.to = 0;
  ack.term = r.term(); ack.accepted = false; ack.sequence = sent.sequence;
  // Backtrack to an empty follower, then acknowledge a full older-term batch.
  while (sent.prev > 0) {
    r.receive(ack); out = r.drain(); CHECK(out.size() == 1);
    sent = out.back(); ack.sequence = sent.sequence;
  }
  ack.accepted = true; ack.matched = 16;
  r.receive(ack);
  CHECK(r.committed() == 0);
  CHECK(r.state().empty());
  out = r.drain(); CHECK(out.size() == 1);
  ack.sequence = out.back().sequence; ack.matched = 18;
  r.receive(ack);
  CHECK(r.committed() == 18);
  CHECK(r.applicationCount() == 1);
}

void votesAndStaleMessages() {
  const std::vector<NodeId> ids = {0, 1, 2};
  Raft r(0, ids, 150);
  Message vote; vote.kind = Kind::Vote; vote.to = 0; vote.from = 1; vote.term = 2;
  r.receive(vote); CHECK(r.drain().back().accepted);
  vote.from = 2; r.receive(vote); CHECK(!r.drain().back().accepted);
  vote.term = 1; r.receive(vote); CHECK(!r.drain().back().accepted);
  vote.from = 99; vote.term = 500; r.receive(vote); CHECK(r.term() == 2);
  Message a; a.kind = Kind::Append; a.from = 1; a.to = 0; a.term = 2;
  a.entries.push_back(Entry(2, "x", "y")); a.commit = 1;
  r.receive(a); CHECK(r.committed() == 1); r.drain();
  vote.from = 2; vote.term = 3; r.receive(vote); CHECK(!r.drain().back().accepted);
  CHECK(r.state().at("x") == "y");
  bool threw = false;
  r.tick(10); try { r.tick(9); } catch (const std::invalid_argument&) { threw = true; }
  CHECK(threw);
}

void reorderedAndLost() {
  Cluster c(3); c.run(500);
  NodeId leader = c.leader();
  CHECK(c.nodes[leader]->propose("retry", "value"));
  c.collect();
  std::deque<Message> delayed; delayed.swap(c.queue);
  c.run(100);
  while (!delayed.empty()) { c.queue.push_front(delayed.front()); delayed.pop_front(); }
  c.flush(true); c.run(100);
  for (size_t i = 0; i < c.nodes.size(); ++i) CHECK(c.nodes[i]->applicationCount() == 1);
}

void injectedTimeoutsAndCandidate() {
  const std::vector<NodeId> ids = {0, 1, 2};
  unsigned calls = 0;
  Raft r(0, ids, 150, 30, [&calls](NodeId id, Term term, uint64_t base) {
    CHECK(id == 0); CHECK(base == 150);
    ++calls;
    return uint64_t(term == 0 ? 175 : 240);
  });
  CHECK(calls == 1);
  r.tick(174); CHECK(r.role() == Role::Follower);
  r.tick(175); CHECK(r.role() == Role::Candidate); CHECK(calls == 2);
  r.tick(414); CHECK(r.term() == 1);
  r.tick(415); CHECK(r.term() == 2); CHECK(calls == 3);
  r.drain();
  Message a; a.kind = Kind::Append; a.from = 1; a.to = 0; a.term = 2;
  a.entries.push_back(Entry(2, "committed-only", "value"));
  r.receive(a);
  CHECK(r.role() == Role::Follower); CHECK(r.leader() == 1);
  CHECK(r.drain().back().accepted); CHECK(r.state().empty());
  a.commit = 1; r.receive(a);
  CHECK(r.state().at("committed-only") == "value");
  r.tick(654); CHECK(r.role() == Role::Follower);
  r.tick(655); CHECK(r.role() == Role::Candidate);
  bool rejected = false;
  try { Raft bad(0, ids, 150, 30, [](NodeId, Term, uint64_t) { return uint64_t(30); }); }
  catch (const std::invalid_argument&) { rejected = true; }
  CHECK(rejected);

  // Injected, seeded PRNG lives in the caller; identical seeds are reproducible.
  uint32_t seedA = 7, seedB = 7;
  Raft::ElectionTimeout generatorA = [&seedA](NodeId, Term, uint64_t base) {
    seedA = seedA * 1664525u + 1013904223u; return base + seedA % 100;
  };
  Raft::ElectionTimeout generatorB = [&seedB](NodeId, Term, uint64_t base) {
    seedB = seedB * 1664525u + 1013904223u; return base + seedB % 100;
  };
  Raft x(0, ids, 150, 30, generatorA), y(0, ids, 150, 30, generatorB);
  for (uint64_t t = 0; t < 2000; ++t) {
    x.tick(t); y.tick(t); CHECK(x.term() == y.term()); x.drain(); y.drain();
  }
  CHECK(seedA == seedB); CHECK(x.term() > 3);
}

void correlatedResponses() {
  const std::vector<NodeId> ids = {0, 1, 2};
  Raft r(0, ids, 150);
  r.tick(150); r.drain();
  Message vote; vote.kind = Kind::VoteReply; vote.from = 1; vote.to = 0;
  vote.term = r.term(); vote.accepted = true; r.receive(vote);
  std::vector<Message> out = r.drain();
  Message first = out.front(); CHECK(first.to == 1);
  CHECK(r.propose("correlation", "value")); r.drain();
  Message ack; ack.kind = Kind::AppendReply; ack.from = 1; ack.to = 0;
  ack.term = r.term(); ack.accepted = true; ack.sequence = first.sequence;
  ack.matched = 2; r.receive(ack); // This request sent only index 1.
  CHECK(r.committed() == 0); CHECK(r.drain().empty());
  ack.matched = 1; ack.sequence = out.back().sequence; r.receive(ack);
  CHECK(r.committed() == 0); // Another peer's sequence must not count.
  r.tick(240); out = r.drain();
  CHECK(out.front().sequence == first.sequence); // RTT may exceed heartbeat.
  ack.sequence = first.sequence; r.receive(ack);
  CHECK(r.committed() == 1); CHECK(r.state().empty());
  out = r.drain(); CHECK(out.size() == 1);
  Message second = out.front(); CHECK(second.prev == 1);
  Message stale = ack; stale.accepted = false;
  r.receive(stale); CHECK(r.drain().empty());
  ack.sequence = second.sequence; ack.matched = 2; r.receive(ack);
  CHECK(r.state().at("correlation") == "value");
  r.receive(stale); r.receive(ack); CHECK(r.drain().empty());
  r.tick(270); out = r.drain();
  CHECK(out.front().to == 1); CHECK(out.front().prev == 2);
}

void retryAcrossLeaderChange() {
  Cluster c(3); c.run(500);
  NodeId old = c.leader(); c.isolated.insert(old);
  CHECK(c.nodes[old]->propose("stable-id", "same-value"));
  c.flush(); CHECK(c.nodes[old]->state().empty());
  c.run(600);
  NodeId fresh = c.leader(); CHECK(fresh != old);
  CHECK(c.nodes[fresh]->propose("stable-id", "same-value"));
  c.flush(); c.run(100);
  c.isolated.clear(); c.run(400, true);
  CHECK(c.nodes[c.leader()]->propose("stable-id", "same-value"));
  for (size_t i = 0; i < c.nodes.size(); ++i) {
    CHECK(c.nodes[i]->applicationCount() == 1);
    CHECK(c.nodes[i]->state().at("stable-id") == "same-value");
    unsigned occurrences = 0;
    for (Index j = 1; j <= c.nodes[i]->lastIndex(); ++j)
      if (c.nodes[i]->log()[j].request == "stable-id") ++occurrences;
    CHECK(occurrences == 1);
  }
}

void observerTransitions() {
  Cluster c(3); c.run(500);
  NodeId leader = c.leader();
  unsigned commits = 0, applies = 0;
  c.nodes[leader]->setObserver([&](bool applied, bool majority, Index index, const Entry& entry) {
    if (entry.request != "observed") return;
    CHECK(c.nodes[leader]->committed() >= index);
    if (!applied) {
      CHECK(majority); CHECK(c.nodes[leader]->state().count("observed") == 0); ++commits;
    } else {
      CHECK(commits == 1); CHECK(c.nodes[leader]->state().count("observed") == 1); ++applies;
    }
  });
  CHECK(c.nodes[leader]->propose("observed", "value"));
  CHECK(commits == 0 && applies == 0);
  c.flush(true); c.run(100);
  CHECK(commits == 1 && applies == 1);
}

void boundedRetry() {
  const std::vector<NodeId> ids = {0, 1, 2};
  Raft leader(0, ids, 150, 30), follower(1, ids, 200, 30);
  leader.setRetryPolicy(100, 400);
  leader.tick(150); leader.drain();
  Message vote; vote.kind = Kind::VoteReply; vote.from = 1; vote.to = 0;
  vote.term = 1; vote.accepted = true; leader.receive(vote);
  std::vector<Message> out = leader.drain();
  Message noop = out.front(); CHECK(noop.to == 1);
  follower.receive(noop); leader.receive(follower.drain().front()); leader.drain();
  CHECK(leader.committed() == 1);
  CHECK(leader.propose("bounded", "value")); out = leader.drain();
  Message data; for (const Message& m : out) if (m.to == 1) data = m;
  CHECK(data.entries.size() == 1);
  // Deliver heartbeats but hold all data; neither missing data nor a second
  // follower may be inferred from heartbeat success.
  unsigned retransmits = 0;
  for (uint64_t now = 180; now <= 570; now += 30) {
    leader.tick(now); out = leader.drain();
    for (const Message& m : out) if (m.to == 1 && !m.entries.empty()) {
      CHECK(m.sequence == data.sequence);
      CHECK(now == 270 || now == 480); ++retransmits;
    }
    for (const Message& m : out) if (m.to == 1 && m.entries.empty()) {
      CHECK(m.prev == 1 && m.lastTerm == 1);
      follower.tick(now); follower.drain(); follower.receive(m);
      for (const Message& ack : follower.drain()) leader.receive(ack);
    }
    CHECK(leader.committed() == 1); CHECK(follower.role() == Role::Follower);
    leader.drain();
  }
  CHECK(retransmits == 2);
  follower.receive(data); Message ack = follower.drain().front();
  Message bad = ack; ++bad.matched; leader.receive(bad);
  CHECK(leader.committed() == 1);
  leader.receive(ack); CHECK(leader.committed() == 2);
  leader.receive(ack); bad = ack; bad.accepted = false; leader.receive(bad);
  CHECK(leader.committed() == 2);
  Message higher; higher.kind = Kind::Append; higher.from = 2; higher.to = 0;
  higher.term = 2; higher.sequence = 999; leader.receive(higher); leader.drain();
  leader.receive(ack); leader.tick(580);
  CHECK(leader.role() == Role::Follower && leader.drain().empty());
  CHECK(leader.applicationCount() == 1);
}

void pendingDataHeartbeatSafety() {
  const std::vector<NodeId> ids = {0, 1, 2};
  Raft leader(0, ids, 150, 30), follower(1, ids, 200, 30);
  leader.setRetryPolicy(100, 400);
  leader.tick(150); leader.drain();
  Message vote; vote.kind = Kind::VoteReply; vote.from = 1; vote.to = 0;
  vote.term = 1; vote.accepted = true; leader.receive(vote);
  std::vector<Message> out = leader.drain();
  Message noop = out.front(); CHECK(noop.to == 1);
  follower.receive(noop); leader.receive(follower.drain().front()); leader.drain();
  CHECK(leader.propose("held-ack", "original"));
  out = leader.drain();
  Message data;
  for (const Message& m : out) if (m.to == 1) data = m;
  follower.receive(data);
  const Message held = follower.drain().front();
  CHECK(held.accepted && held.matched == 2);
  CHECK(follower.lastIndex() == 2 && follower.committed() == 1);
  CHECK(leader.propose("queued-behind", "later"));
  out = leader.drain();
  // A received suffix with its ACK lost must survive the older-prefix heartbeat.
  for (const Message& m : out) if (m.to == 1) {
    CHECK(m.entries.empty() && m.prev == 1 && m.sequence != data.sequence);
    follower.receive(m);
    for (const Message& ack : follower.drain()) leader.receive(ack);
  }
  CHECK(follower.lastIndex() == 2 && follower.log()[2].request == "held-ack");
  CHECK(follower.committed() == 1 && leader.committed() == 1);
  leader.drain(); leader.tick(250); out = leader.drain();
  unsigned retransmits = 0;
  for (const Message& m : out) if (m.to == 1 && !m.entries.empty()) {
    ++retransmits;
    CHECK(m.sequence == data.sequence && m.term == data.term);
    CHECK(m.prev == data.prev && m.lastTerm == data.lastTerm && m.commit == data.commit);
    CHECK(m.entries.size() == data.entries.size());
    CHECK(m.entries[0].term == data.entries[0].term);
    CHECK(m.entries[0].request == data.entries[0].request);
    CHECK(m.entries[0].value == data.entries[0].value);
  }
  CHECK(retransmits == 1);
  Message wrong = held; wrong.matched = 3; leader.receive(wrong);
  CHECK(leader.committed() == 1);
  leader.receive(held); CHECK(leader.committed() == 2);
  out = leader.drain(); CHECK(out.size() == 1);
  CHECK(out[0].prev == 2 && out[0].entries.size() == 1);
  CHECK(out[0].entries[0].request == "queued-behind");
  CHECK(out[0].sequence != data.sequence);
  follower.receive(out[0]);
  CHECK(follower.committed() == 2 && follower.applicationCount() == 1);
  leader.receive(follower.drain().front());
  CHECK(leader.committed() == 3 && leader.applicationCount() == 2);
  follower.receive(data); follower.drain();
  CHECK(follower.lastIndex() == 3 && follower.committed() == 2);
  CHECK(follower.log()[3].request == "queued-behind");
}

int main() {
  try {
    pendingDataHeartbeatSafety(); boundedRetry(); minority(true); observerTransitions();
    basic(1); basic(3); basic(5); basic(50);
    partition(); minority(); currentTermAndIdempotence(); votesAndStaleMessages(); reorderedAndLost();
    injectedTimeoutsAndCandidate(); correlatedResponses(); retryAcrossLeaderChange();
    std::cout << "PASS: injected/reproducible timeouts, candidate stepdown, exact response correlation, delayed ACK, stale failure, cross-leader retry, committed-only application\n";
    std::cout << "PASS: 1/3/5/50 nodes, election, replication, partition repair, minority, current-term commit, idempotence, votes, stale/reordered/duplicate/lost messages\n";
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n'; return 1;
  }
}
