#include "daagka-crypto.h"
#include <cassert>
#include <iostream>
#include <functional>

using namespace daagka;

static void rejects(const std::function<void()>& action) {
  bool threw = false;
  try { action(); } catch (const std::runtime_error&) { threw = true; }
  assert(threw);
}

int main() {
  Bytes session = random_bytes(32);
  Member alice("alice"), bob("bob"), carol("carol");
  std::vector<PublicMember> roster = {
    {alice.id, alice.public_key, {}, {}},
    {bob.id, bob.public_key, {}, {}},
    {carol.id, carol.public_key, {}, {}}
  };
  Member* members[] = {&alice, &bob, &carol};
  for (size_t i = 0; i < roster.size(); ++i) {
    Proof p = prove(*members[i], session, roster);
    roster[i].commitment = p.commitment;
    roster[i].response = p.response;
  }
  verify_roster(session, roster);
  Issued issued = issue(alice, session, roster);
  Bytes t = transcript(session, roster);
  Curve curve;
  Bytes total(32, 0);
  for (const auto& m : roster)
    total = add256(total, contribution(t, curve.shared(alice.secret.get(), m.public_key)));
  Bytes first_shared = curve.shared(bob.secret.get(), alice.public_key);
  assert(contribution(t, first_shared) == contribution(t, curve.shared(alice.secret.get(), bob.public_key)));
  Bytes wrapping = wrap_key(t, alice.id, bob.id, issued.selection.z_public,
                            curve.shared(bob.secret.get(), issued.selection.z_public));
  Bytes material = open(wrapping, aad(t, issued.selection, bob.id), issued.selection.envelopes[1]);
  assert(material.size() == 144);
  Bytes partial(material.begin() + 4, material.begin() + 36);
  assert(add256(partial, contribution(t, first_shared)) == total);
  Bytes gamma(material.begin() + 40, material.begin() + 72);
  assert(key_for(t, total, gamma) == issued.key);
  SelectionState a, b, c;
  assert(receive(alice, session, roster, issued.selection, issued.selection.digest, a) == issued.key);
  assert(receive(bob, session, roster, issued.selection, issued.selection.digest, b) == issued.key);
  assert(receive(carol, session, roster, issued.selection, issued.selection.digest, c) == issued.key);
  rejects([&] { receive(bob, session, roster, issued.selection, issued.selection.digest, b); });

  auto bad_proof = roster;
  bad_proof[1].response[0] ^= 1;
  rejects([&] { verify_roster(session, bad_proof); });
  bad_proof = roster;
  bad_proof[1].commitment = alice.public_key;
  rejects([&] { verify_roster(session, bad_proof); });
  auto bad_point = roster;
  bad_point[1].public_key.assign(33, 0);
  rejects([&] { verify_roster(session, bad_point); });
  auto duplicate = roster;
  duplicate[2].public_key = duplicate[1].public_key;
  rejects([&] { verify_roster(session, duplicate); });
  auto altered_roster = roster;
  altered_roster[2].id = "dave";
  rejects([&] { verify_roster(session, altered_roster); });
  rejects([&] { verify_roster(random_bytes(32), roster); });

  SelectionState fresh;
  auto tamper = issued.selection;
  tamper.envelopes[1].ciphertext[0] ^= 1;
  rejects([&] { receive(bob, session, roster, tamper, issued.selection.digest, fresh); });
  tamper.digest = selection_digest(transcript(session, roster), tamper);
  rejects([&] { receive(bob, session, roster, tamper, tamper.digest, fresh); });
  rejects([&] { receive(bob, session, roster, issued.selection, random_bytes(32), fresh); });
  tamper = issued.selection;
  tamper.proof.response[0] ^= 1;
  rejects([&] { receive(bob, session, roster, tamper, issued.selection.digest, fresh); });
  tamper = issued.selection;
  tamper.envelopes[0].ciphertext[0] ^= 1;
  tamper.digest = selection_digest(t, tamper);
  rejects([&] { receive(bob, session, roster, tamper, tamper.digest, fresh); });
  tamper = issued.selection;
  tamper.envelopes[1].tag[0] ^= 1;
  tamper.digest = selection_digest(transcript(session, roster), tamper);
  rejects([&] { receive(bob, session, roster, tamper, tamper.digest, fresh); });
  tamper = issued.selection;
  tamper.envelopes[1].recipient = "alice";
  tamper.digest = selection_digest(transcript(session, roster), tamper);
  rejects([&] { receive(bob, session, roster, tamper, tamper.digest, fresh); });
  tamper = issued.selection;
  tamper.z_public = bob.public_key;
  tamper.digest = selection_digest(transcript(session, roster), tamper);
  rejects([&] { receive(bob, session, roster, tamper, tamper.digest, fresh); });
  fresh.accepted = random_bytes(32);
  rejects([&] { receive(bob, session, roster, issued.selection, issued.selection.digest, fresh); });
  fresh.accepted = issued.selection.digest;
  assert(receive(bob, session, roster, issued.selection, issued.selection.digest, fresh) == issued.key);
  std::cout << "DAAGKA prototype: three-member agreement and negative cases passed\n";
}
