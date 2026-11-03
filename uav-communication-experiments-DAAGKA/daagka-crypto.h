#ifndef IOT_DAAGKA_CRYPTO_H
#define IOT_DAAGKA_CRYPTO_H

// Standalone C++11/OpenSSL 1.0.2 protocol prototype. This is NOT an
// implementation of an authenticated distributed agreement protocol.
// The application must authenticate the roster, leader identity and the
// committed selection (including its digest), and provide a fresh session
// identifier. A Schnorr proof establishes possession, not identity.
// Algorithm 2 shape: X includes itself in the ordered UEKeys roster, sums
// H2(skX*pkY) modulo 2^256 and encrypts KMALL-H2(KCY), gamma and H5(z*pkY)
// per Y. AES-256-GCM is the concrete E_kappa2; kappa2=H3(z*pkY).
// H2/H3/H5 are domain-separated SHA-256 encodings including session context,
// not unspecified manuscript hash instantiations. UEKeys[] is represented
// by the session/ordered-roster transcript in the encrypted material and GK
// hash. A key commitment and GCM AAD are extra checks. Preselection member
// proofs cover only session/roster; the leader's postselection Schnorr proof
// covers Z and the ordered ciphertexts (including nonces/tags) but does not
// authenticate identity.
// Roster, unused ephemeral authorization, committed digest and replay state
// must be established by the caller; no core authorization or ledger here.
// A malicious initiator can choose inconsistent KM values per recipient;
// this implementation is not a malicious-leader-consistent group protocol.
// No forward secrecy against later exposure of stored ephemeral scalars is
// claimed. Never reuse a Member for another session; erase secrets promptly.

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace daagka {
using Bytes = std::vector<unsigned char>;

template <typename T, void (*Free)(T*)> using Ptr = std::unique_ptr<T, decltype(Free)>;
inline void fail(const char* message) { throw std::runtime_error(message); }
inline void need(bool ok, const char* message) { if (!ok) fail(message); }
inline void append(Bytes& out, const Bytes& value) {
  need(value.size() <= 0xffffffffU, "field too long");
  uint32_t n = static_cast<uint32_t>(value.size());
  for (int i = 3; i >= 0; --i) out.push_back(static_cast<unsigned char>(n >> (8 * i)));
  out.insert(out.end(), value.begin(), value.end());
}
inline void append(Bytes& out, const std::string& value) {
  append(out, Bytes(value.begin(), value.end()));
}
inline Bytes hash(const std::string& domain, const std::vector<Bytes>& fields) {
  Bytes encoded;
  append(encoded, std::string("DAAGKA-prototype-v1/" + domain));
  for (const auto& f : fields) append(encoded, f);
  Bytes result(SHA256_DIGEST_LENGTH);
  SHA256(encoded.data(), encoded.size(), result.data());
  return result;
}
inline Bytes random_bytes(size_t n) {
  need(n <= 0x7fffffffU, "random request too large");
  Bytes value(n);
  if (n) need(RAND_bytes(value.data(), static_cast<int>(n)) == 1, "RAND_bytes failed");
  return value;
}
inline Bytes raw(const std::string& text) { return Bytes(text.begin(), text.end()); }
inline Bytes number(uint32_t n) {
  Bytes out;
  for (int i = 3; i >= 0; --i) out.push_back(static_cast<unsigned char>(n >> (8 * i)));
  return out;
}

struct Curve {
  Ptr<EC_GROUP, EC_GROUP_free> group;
  Ptr<BN_CTX, BN_CTX_free> ctx;
  Ptr<BIGNUM, BN_free> order;
  Curve() : group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free),
            ctx(BN_CTX_new(), BN_CTX_free), order(BN_new(), BN_free) {
    need(group && ctx && order && EC_GROUP_get_order(group.get(), order.get(), ctx.get()) == 1,
         "P-256 initialization failed");
  }
  Bytes point(const EC_POINT* p) const {
    size_t n = EC_POINT_point2oct(group.get(), p, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx.get());
    need(n == 33, "point serialization failed");
    Bytes out(n);
    need(EC_POINT_point2oct(group.get(), p, POINT_CONVERSION_COMPRESSED,
                            out.data(), out.size(), ctx.get()) == n, "point serialization failed");
    return out;
  }
  Ptr<EC_POINT, EC_POINT_free> parse(const Bytes& bytes) const {
    need(bytes.size() == 33 && (bytes[0] == 2 || bytes[0] == 3), "invalid point encoding");
    Ptr<EC_POINT, EC_POINT_free> p(EC_POINT_new(group.get()), EC_POINT_free);
    need(p && EC_POINT_oct2point(group.get(), p.get(), bytes.data(), bytes.size(), ctx.get()) == 1 &&
         EC_POINT_is_at_infinity(group.get(), p.get()) == 0 &&
         EC_POINT_is_on_curve(group.get(), p.get(), ctx.get()) == 1 && point(p.get()) == bytes,
         "invalid curve point");
    return p;
  }
  Ptr<BIGNUM, BN_clear_free> scalar() const {
    Ptr<BIGNUM, BN_clear_free> s(BN_new(), BN_clear_free);
    need(static_cast<bool>(s), "scalar allocation failed");
    Bytes b;
    do {
      b = random_bytes(32);
      need(BN_bin2bn(b.data(), static_cast<int>(b.size()), s.get()) != NULL, "scalar conversion failed");
      OPENSSL_cleanse(b.data(), b.size());
    } while (BN_is_zero(s.get()) || BN_cmp(s.get(), order.get()) >= 0);
    return s;
  }
  Bytes base(const BIGNUM* s) const {
    Ptr<EC_POINT, EC_POINT_free> p(EC_POINT_new(group.get()), EC_POINT_free);
    need(p && EC_POINT_mul(group.get(), p.get(), s, NULL, NULL, ctx.get()) == 1,
         "base multiplication failed");
    return point(p.get());
  }
  Bytes shared(const BIGNUM* s, const Bytes& peer) const {
    auto p = parse(peer);
    Ptr<EC_POINT, EC_POINT_free> out(EC_POINT_new(group.get()), EC_POINT_free);
    need(out && EC_POINT_mul(group.get(), out.get(), NULL, p.get(), s, ctx.get()) == 1 &&
         EC_POINT_is_at_infinity(group.get(), out.get()) == 0, "ECDH failed");
    return point(out.get());
  }
};

struct PublicMember {
  std::string id;
  Bytes public_key;
  Bytes commitment;
  Bytes response;
};
struct Proof { Bytes commitment, response; };
struct Member {
  std::string id;
  Bytes public_key;
  Ptr<BIGNUM, BN_clear_free> secret;
  explicit Member(const std::string& name) : id(name), secret(nullptr, BN_clear_free) {
    need(!id.empty(), "empty member id");
    Curve c;
    secret = c.scalar();
    public_key = c.base(secret.get());
  }
  Member(Member&&) = default;
  Member& operator=(Member&&) = default;
  Member(const Member&) = delete;
  Member& operator=(const Member&) = delete;
};
inline Bytes transcript(const Bytes& session, const std::vector<PublicMember>& roster) {
  need(!session.empty() && !roster.empty() && roster.size() <= 50, "invalid session or roster");
  Curve c;
  Bytes packed;
  append(packed, session);
  std::set<std::string> ids;
  std::set<Bytes> points;
  std::string previous;
  for (const auto& m : roster) {
    need(!m.id.empty() && (previous.empty() || previous < m.id) && ids.insert(m.id).second &&
         points.insert(m.public_key).second, "unsorted or duplicate roster");
    c.parse(m.public_key);
    append(packed, m.id);
    append(packed, m.public_key);
    previous = m.id;
  }
  return hash("session-roster", {packed});
}
inline Ptr<BIGNUM, BN_clear_free> challenge(const Curve& c, const Bytes& digest,
                                             const PublicMember& m, const Bytes& r) {
  Bytes h = hash("schnorr-challenge", {digest, raw(m.id), m.public_key, r});
  Ptr<BIGNUM, BN_clear_free> v(BN_bin2bn(h.data(), static_cast<int>(h.size()), NULL), BN_clear_free);
  need(v && BN_mod(v.get(), v.get(), c.order.get(), c.ctx.get()) == 1, "challenge failed");
  return v;
}
inline Proof prove(const Member& member, const Bytes& session,
                   const std::vector<PublicMember>& roster) {
  Bytes t = transcript(session, roster);
  auto found = std::find_if(roster.begin(), roster.end(), [&](const PublicMember& p) {
    return p.id == member.id && p.public_key == member.public_key;
  });
  need(found != roster.end() && member.secret, "member not in roster");
  Curve c;
  auto k = c.scalar();
  Proof proof;
  proof.commitment = c.base(k.get());
  auto e = challenge(c, t, *found, proof.commitment);
  Ptr<BIGNUM, BN_clear_free> s(BN_new(), BN_clear_free);
  need(s && BN_mod_mul(s.get(), e.get(), member.secret.get(), c.order.get(), c.ctx.get()) == 1 &&
         BN_mod_add(s.get(), s.get(), k.get(), c.order.get(), c.ctx.get()) == 1,
         "proof construction failed");
  proof.response.assign(32, 0);
  int width = BN_num_bytes(s.get());
  need(width >= 0 && width <= 32 &&
       BN_bn2bin(s.get(), proof.response.data() + 32 - width) == width,
       "proof encoding failed");
  return proof;
}
inline void verify_roster(const Bytes& session, const std::vector<PublicMember>& roster) {
  Bytes t = transcript(session, roster);
  Curve c;
  for (const auto& m : roster) {
    auto p = c.parse(m.public_key);
    auto r = c.parse(m.commitment);
    need(m.response.size() == 32, "invalid proof response length");
    Ptr<BIGNUM, BN_clear_free> s(BN_bin2bn(m.response.data(), 32, NULL), BN_clear_free);
    need(s && BN_cmp(s.get(), c.order.get()) < 0, "invalid proof scalar");
    auto e = challenge(c, t, m, m.commitment);
    Ptr<EC_POINT, EC_POINT_free> lhs(EC_POINT_new(c.group.get()), EC_POINT_free);
    Ptr<EC_POINT, EC_POINT_free> rhs(EC_POINT_new(c.group.get()), EC_POINT_free);
    need(lhs && rhs && EC_POINT_mul(c.group.get(), lhs.get(), s.get(), NULL, NULL, c.ctx.get()) == 1 &&
         EC_POINT_mul(c.group.get(), rhs.get(), NULL, p.get(), e.get(), c.ctx.get()) == 1 &&
         EC_POINT_add(c.group.get(), rhs.get(), rhs.get(), r.get(), c.ctx.get()) == 1 &&
         EC_POINT_cmp(c.group.get(), lhs.get(), rhs.get(), c.ctx.get()) == 0,
         "Schnorr proof rejected");
  }
}
inline Bytes add256(const Bytes& a, const Bytes& b, bool subtract = false) {
  need(a.size() == 32 && b.size() == 32, "invalid 256-bit operand");
  Bytes result(32);
  int carry = 0;
  for (int i = 31; i >= 0; --i) {
    int value = static_cast<int>(a[i]) + (subtract ? -static_cast<int>(b[i]) : b[i]) + carry;
    result[i] = static_cast<unsigned char>(value & 255);
    carry = value >> 8;
  }
  return result;
}
inline Bytes contribution(const Bytes& t, const Bytes& shared_point) {
  return hash("H2/KC", {t, shared_point});
}
inline Bytes key_for(const Bytes& t, const Bytes& total, const Bytes& gamma) {
  return hash("H3/group-key", {t, total, gamma});
}
inline Bytes wrap_key(const Bytes& t, const std::string& leader, const std::string& recipient,
                      const Bytes& z_public, const Bytes& shared_point) {
  return hash("H3/wrap-key", {t, raw(leader), raw(recipient), z_public, shared_point});
}
inline Bytes kappa1(const Bytes& t, const std::string& leader, const std::string& recipient,
                    const Bytes& z_public, const Bytes& shared_point) {
  return hash("H5/wrap-check", {t, raw(leader), raw(recipient), z_public, shared_point});
}
struct Envelope {
  std::string recipient;
  Bytes nonce, ciphertext, tag;
};
struct Selection {
  std::string leader;
  Bytes z_public, key_commitment, digest;
  std::vector<Envelope> envelopes;
  Proof proof;
};
inline Bytes aad(const Bytes& t, const Selection& s, const std::string& recipient) {
  return hash("gcm-aad", {t, raw(s.leader), raw(recipient), s.z_public, s.key_commitment});
}
inline Envelope seal(const Bytes& key, const Bytes& associated, const Bytes& plaintext,
                     const std::string& recipient) {
  need(key.size() == 32 && plaintext.size() <= 0x7fffffffU, "invalid encryption input");
  Envelope e;
  e.recipient = recipient;
  e.nonce = random_bytes(12);
  e.ciphertext.resize(plaintext.size());
  e.tag.resize(16);
  Ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  int n = 0, final_n = 0;
  need(ctx && EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
         EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key.data(), e.nonce.data()) == 1 &&
         EVP_EncryptUpdate(ctx.get(), NULL, &n, associated.data(), static_cast<int>(associated.size())) == 1 &&
         EVP_EncryptUpdate(ctx.get(), e.ciphertext.data(), &n, plaintext.data(),
                           static_cast<int>(plaintext.size())) == 1 &&
         EVP_EncryptFinal_ex(ctx.get(), e.ciphertext.data() + n, &final_n) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, e.tag.data()) == 1,
         "encryption failed");
  return e;
}
inline Bytes open(const Bytes& key, const Bytes& associated, const Envelope& e) {
  need(key.size() == 32 && e.nonce.size() == 12 && e.tag.size() == 16 &&
       e.ciphertext.size() <= 0x7fffffffU && associated.size() <= 0x7fffffffU,
       "invalid ciphertext fields");
  Bytes result(e.ciphertext.size());
  Ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  int n = 0, final_n = 0;
  bool valid = ctx && EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
      EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key.data(), e.nonce.data()) == 1 &&
      EVP_DecryptUpdate(ctx.get(), NULL, &n, associated.data(), static_cast<int>(associated.size())) == 1 &&
      EVP_DecryptUpdate(ctx.get(), result.data(), &n, e.ciphertext.data(),
                        static_cast<int>(e.ciphertext.size())) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                          const_cast<unsigned char*>(e.tag.data())) == 1 &&
      EVP_DecryptFinal_ex(ctx.get(), result.data() + n, &final_n) == 1;
  if (!valid) {
    if (!result.empty()) OPENSSL_cleanse(result.data(), result.size());
    fail("ciphertext authentication failed");
  }
  return result;
}
inline Bytes selection_digest(const Bytes& t, const Selection& s) {
  Bytes packed;
  append(packed, s.leader);
  append(packed, s.z_public);
  append(packed, s.key_commitment);
  for (const auto& e : s.envelopes) {
    append(packed, e.recipient);
    append(packed, e.nonce);
    append(packed, e.ciphertext);
    append(packed, e.tag);
  }
  return hash("selection", {t, packed});
}
inline Bytes proof_transcript(const Bytes& t, const Selection& s) {
  return hash("leader-proof-transcript", {t, selection_digest(t, s)});
}
inline void verify_selection_proof(const Bytes& t, const Selection& s,
                                   const PublicMember& leader) {
  Curve c;
  auto p = c.parse(leader.public_key);
  auto r = c.parse(s.proof.commitment);
  need(s.proof.response.size() == 32, "invalid selection proof length");
  Ptr<BIGNUM, BN_clear_free> scalar(BN_bin2bn(s.proof.response.data(), 32, NULL), BN_clear_free);
  need(scalar && BN_cmp(scalar.get(), c.order.get()) < 0, "invalid selection proof scalar");
  auto e = challenge(c, proof_transcript(t, s), leader, s.proof.commitment);
  Ptr<EC_POINT, EC_POINT_free> lhs(EC_POINT_new(c.group.get()), EC_POINT_free);
  Ptr<EC_POINT, EC_POINT_free> rhs(EC_POINT_new(c.group.get()), EC_POINT_free);
  need(lhs && rhs && EC_POINT_mul(c.group.get(), lhs.get(), scalar.get(), NULL, NULL, c.ctx.get()) == 1 &&
       EC_POINT_mul(c.group.get(), rhs.get(), NULL, p.get(), e.get(), c.ctx.get()) == 1 &&
       EC_POINT_add(c.group.get(), rhs.get(), rhs.get(), r.get(), c.ctx.get()) == 1 &&
       EC_POINT_cmp(c.group.get(), lhs.get(), rhs.get(), c.ctx.get()) == 0,
       "selection proof rejected");
}
inline const PublicMember& lookup(const std::vector<PublicMember>& roster, const std::string& id) {
  auto it = std::find_if(roster.begin(), roster.end(), [&](const PublicMember& m) { return m.id == id; });
  need(it != roster.end(), "unknown member");
  return *it;
}
inline Proof sign_selection(const Member& signer, const PublicMember& public_signer,
                            const Bytes& digest) {
  Curve c;
  auto k = c.scalar();
  Proof proof;
  proof.commitment = c.base(k.get());
  auto e = challenge(c, digest, public_signer, proof.commitment);
  Ptr<BIGNUM, BN_clear_free> s(BN_new(), BN_clear_free);
  need(s && BN_mod_mul(s.get(), e.get(), signer.secret.get(), c.order.get(), c.ctx.get()) == 1 &&
       BN_mod_add(s.get(), s.get(), k.get(), c.order.get(), c.ctx.get()) == 1,
       "selection proof construction failed");
  proof.response.assign(32, 0);
  int width = BN_num_bytes(s.get());
  need(width >= 0 && width <= 32 &&
       BN_bn2bin(s.get(), proof.response.data() + 32 - width) == width,
       "selection proof encoding failed");
  return proof;
}
struct Issued { Selection selection; Bytes key; };
inline Issued issue(const Member& leader, const Bytes& session,
                    const std::vector<PublicMember>& roster) {
  verify_roster(session, roster);
  need(leader.secret && lookup(roster, leader.id).public_key == leader.public_key,
       "unauthorized leader key");
  Bytes t = transcript(session, roster);
  Curve c;
  auto z = c.scalar();
  Issued out;
  out.selection.leader = leader.id;
  out.selection.z_public = c.base(z.get());
  Bytes total(32, 0);
  std::vector<Bytes> contributions;
  for (const auto& m : roster) {
    contributions.push_back(contribution(t, c.shared(leader.secret.get(), m.public_key)));
    total = add256(total, contributions.back());
  }
  Bytes gamma = random_bytes(32);
  out.key = key_for(t, total, gamma);
  out.selection.key_commitment = hash("key-commitment", {t, out.key});
  for (size_t i = 0; i < roster.size(); ++i) {
    const auto& m = roster[i];
    Bytes shared = c.shared(z.get(), m.public_key);
    Bytes wrapping = wrap_key(t, leader.id, m.id, out.selection.z_public, shared);
    Bytes plaintext;
    append(plaintext, add256(total, contributions[i], true));
    append(plaintext, gamma);
    append(plaintext, kappa1(t, leader.id, m.id, out.selection.z_public, shared));
    append(plaintext, t);
    out.selection.envelopes.push_back(seal(wrapping, aad(t, out.selection, m.id), plaintext, m.id));
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    OPENSSL_cleanse(wrapping.data(), wrapping.size());
  }
  out.selection.digest = selection_digest(t, out.selection);
  out.selection.proof = sign_selection(leader, lookup(roster, leader.id), proof_transcript(t, out.selection));
  return out;
}
// The caller supplies the digest from an authenticated/committed selection,
// NOT from the untrusted Selection argument. State persists for the session.
struct SelectionState {
  Bytes accepted;
  bool consumed = false;
};
inline Bytes receive(const Member& member, const Bytes& session,
                     const std::vector<PublicMember>& roster, const Selection& selection,
                     const Bytes& committed_digest, SelectionState& state) {
  need(!state.consumed, "selection replay");
  verify_roster(session, roster);
  need(member.secret && lookup(roster, member.id).public_key == member.public_key,
       "recipient not in roster");
  const PublicMember& leader = lookup(roster, selection.leader);
  Bytes t = transcript(session, roster);
  Curve c;
  c.parse(selection.z_public);
  need(committed_digest.size() == 32 && selection.key_commitment.size() == 32 &&
       selection.digest == committed_digest && selection_digest(t, selection) == committed_digest,
       "uncommitted or modified selection");
  need(state.accepted.empty() || state.accepted == committed_digest, "conflicting selection");
  verify_selection_proof(t, selection, leader);
  need(selection.envelopes.size() == roster.size(), "incomplete selection");
  const Envelope* mine = NULL;
  for (size_t i = 0; i < roster.size(); ++i) {
    need(selection.envelopes[i].recipient == roster[i].id, "duplicate or reordered recipient");
    if (roster[i].id == member.id) mine = &selection.envelopes[i];
  }
  need(mine != NULL, "missing envelope");
  Bytes shared = c.shared(member.secret.get(), selection.z_public);
  Bytes wrapping = wrap_key(t, selection.leader, member.id, selection.z_public, shared);
  Bytes plaintext = open(wrapping, aad(t, selection, member.id), *mine);
  OPENSSL_cleanse(wrapping.data(), wrapping.size());
  Bytes expected_kappa1 = kappa1(t, selection.leader, member.id, selection.z_public, shared);
  // Four length-prefixed 32-byte values: KMY, gamma, kappa1, roster transcript.
  need(plaintext.size() == 144, "invalid recipient material length");
  bool fields_ok = plaintext[0] == 0 && plaintext[1] == 0 && plaintext[2] == 0 && plaintext[3] == 32 &&
                   plaintext[36] == 0 && plaintext[37] == 0 && plaintext[38] == 0 && plaintext[39] == 32 &&
                   plaintext[72] == 0 && plaintext[73] == 0 && plaintext[74] == 0 && plaintext[75] == 32 &&
                   plaintext[108] == 0 && plaintext[109] == 0 && plaintext[110] == 0 && plaintext[111] == 32 &&
                   std::equal(expected_kappa1.begin(), expected_kappa1.end(), plaintext.begin() + 76) &&
                   std::equal(t.begin(), t.end(), plaintext.begin() + 112);
  Bytes partial(plaintext.begin() + 4, plaintext.begin() + 36);
  Bytes gamma(plaintext.begin() + 40, plaintext.begin() + 72);
  Bytes own = contribution(t, c.shared(member.secret.get(), leader.public_key));
  Bytes total = add256(partial, own);
  Bytes key = key_for(t, total, gamma);
  bool commitment_ok = hash("key-commitment", {t, key}) == selection.key_commitment;
  OPENSSL_cleanse(plaintext.data(), plaintext.size());
  need(fields_ok && commitment_ok, "contribution or selected key mismatch");
  state.accepted = committed_digest;
  state.consumed = true;
  return key;
}
} // namespace daagka
#endif
