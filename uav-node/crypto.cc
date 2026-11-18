#include "crypto.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <initializer_list>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <utility>

namespace gka {
void Erase(std::string& value) {
  if (!value.empty()) OPENSSL_cleanse(&value[0], value.size());
  value.clear();
}
KeyPair::~KeyPair() { Erase(secret); }
KeyPair::KeyPair(KeyPair&& other) noexcept {
  secret.swap(other.secret); publicKey.swap(other.publicKey);
}
KeyPair& KeyPair::operator=(KeyPair&& other) noexcept {
  if (this != &other) { Erase(secret); secret.swap(other.secret); publicKey.swap(other.publicKey); }
  return *this;
}
KeyPair& KeyPair::operator=(const KeyPair& other) {
  if (this != &other) { KeyPair copy(other); *this = std::move(copy); }
  return *this;
}
Issued::~Issued() { Erase(key); }
Issued::Issued(Issued&& other) noexcept {
  material.swap(other.material); key.swap(other.key);
}
Issued& Issued::operator=(Issued&& other) noexcept {
  if (this != &other) { Erase(key); key.swap(other.key); material.swap(other.material); }
  return *this;
}
Issued& Issued::operator=(const Issued& other) {
  if (this != &other) { Issued copy(other); *this = std::move(copy); }
  return *this;
}

namespace {
using Number = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using Point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_clear_free)>;
using Group = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using Context = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

void Require(bool valid, const char* reason) {
  if (!valid) throw std::runtime_error(reason);
}
struct Secret {
  std::string value;
  Secret() = default;
  explicit Secret(std::string bytes) { value.swap(bytes); }
  Secret(Secret&& other) noexcept { value.swap(other.value); }
  Secret& operator=(Secret&& other) noexcept {
    if (this != &other) { Erase(value); value.swap(other.value); }
    return *this;
  }
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  ~Secret() { Erase(value); }
};
Number NewNumber() {
  Number value(BN_new(), BN_clear_free);
  Require(static_cast<bool>(value), "BN allocation failed");
  return value;
}
Number DecodeNumber(const std::string& bytes) {
  Require(bytes.size() == 32, "scalar must be 32 bytes");
  Number value(BN_bin2bn(reinterpret_cast<const unsigned char*>(bytes.data()), 32, NULL), BN_clear_free);
  Require(static_cast<bool>(value), "BN decoding failed");
  return value;
}
std::string EncodeNumber(const BIGNUM* value) {
  const int count = BN_num_bytes(value);
  Require(!BN_is_negative(value) && count <= 32, "scalar does not fit 32 bytes");
  std::string out(32, '\0');
  if (count) Require(BN_bn2bin(value, reinterpret_cast<unsigned char*>(&out[32 - count])) == count,
                     "BN encoding failed");
  return out;
}
std::string Hash(int domain, std::initializer_list<const std::string*> values) {
  Require(domain >= 1 && domain <= 5, "invalid hash domain");
  // Distinct fixed ASCII prefixes avoid any cross-function hash reuse. Following
  // arguments have the manuscript's exact order and fixed-width encodings.
  const std::string prefix = "IoT-GKA-H" + std::to_string(domain);
  struct HashContext {
    SHA256_CTX value;
    ~HashContext() { OPENSSL_cleanse(&value, sizeof(value)); }
  } context;
  Require(SHA256_Init(&context.value) == 1, "SHA-256 init failed");
  Require(SHA256_Update(&context.value, prefix.data(), prefix.size()) == 1, "SHA-256 update failed");
  for (const std::string* value : values)
    Require(SHA256_Update(&context.value, value->data(), value->size()) == 1, "SHA-256 update failed");
  std::string result(32, '\0');
  const int ok = SHA256_Final(reinterpret_cast<unsigned char*>(&result[0]), &context.value);
  Require(ok == 1, "SHA-256 final failed");
  return result;
}

class Curve {
 public:
  Group group;
  Context ctx;
  Number order;
  Number field;
  Curve() : group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free),
            ctx(BN_CTX_new(), BN_CTX_free), order(NewNumber()), field(NewNumber()) {
    Require(group && ctx, "EC allocation failed");
    Require(EC_GROUP_get_order(group.get(), order.get(), ctx.get()) == 1, "curve order failed");
    Require(EC_GROUP_get_curve_GFp(group.get(), field.get(), NULL, NULL, ctx.get()) == 1,
            "curve field failed");
  }
  Point NewPoint() const {
    Point point(EC_POINT_new(group.get()), EC_POINT_clear_free);
    Require(static_cast<bool>(point), "EC point allocation failed");
    return point;
  }
  Point DecodePoint(const std::string& bytes) const {
    Require(bytes.size() == 64, "point must be x32 || y32");
    auto x = DecodeNumber(bytes.substr(0, 32));
    auto y = DecodeNumber(bytes.substr(32, 32));
    Require(BN_cmp(x.get(), field.get()) < 0 && BN_cmp(y.get(), field.get()) < 0,
            "point coordinates are not canonical");
    auto point = NewPoint();
    Require(EC_POINT_set_affine_coordinates_GFp(group.get(), point.get(), x.get(), y.get(), ctx.get()) == 1,
            "invalid curve point");
    Require(EC_POINT_is_on_curve(group.get(), point.get(), ctx.get()) == 1 &&
            EC_POINT_is_at_infinity(group.get(), point.get()) == 0, "invalid or identity point");
    // P-256 has cofactor one; every valid nonidentity point is in its prime-order group.
    return point;
  }
  std::string EncodePoint(const EC_POINT* point) const {
    auto x = NewNumber(); auto y = NewNumber();
    Require(EC_POINT_get_affine_coordinates_GFp(group.get(), point, x.get(), y.get(), ctx.get()) == 1,
            "point encoding failed");
    Secret xBytes(EncodeNumber(x.get())), yBytes(EncodeNumber(y.get()));
    std::string encoded; encoded.reserve(64);
    encoded.append(xBytes.value).append(yBytes.value);
    return encoded;
  }
  Number Scalar(const std::string& bytes) const {
    auto value = DecodeNumber(bytes);
    Require(!BN_is_zero(value.get()) && BN_cmp(value.get(), order.get()) < 0, "invalid private scalar");
    BN_set_flags(value.get(), BN_FLG_CONSTTIME);
    return value;
  }
  Number H1(std::initializer_list<const std::string*> values) const {
    Secret hash(Hash(1, values));
    auto value = DecodeNumber(hash.value); auto qm1 = NewNumber();
    Require(BN_copy(qm1.get(), order.get()) != NULL && BN_sub_word(qm1.get(), 1) == 1,
            "H1 modulus failed");
    Require(BN_mod(value.get(), value.get(), qm1.get(), ctx.get()) == 1 &&
            BN_add_word(value.get(), 1) == 1, "H1 scalar mapping failed");
    BN_set_flags(value.get(), BN_FLG_CONSTTIME);
    return value;
  }
  Number RandomScalar() const {
    auto scalar = NewNumber();
    do { Require(BN_rand_range(scalar.get(), order.get()) == 1, "scalar RNG failed"); }
    while (BN_is_zero(scalar.get()));
    BN_set_flags(scalar.get(), BN_FLG_CONSTTIME);
    return scalar;
  }
  std::string Public(const BIGNUM* scalar) const {
    auto point = NewPoint();
    Require(EC_POINT_mul(group.get(), point.get(), scalar, NULL, NULL, ctx.get()) == 1,
            "public key multiplication failed");
    return EncodePoint(point.get());
  }
  std::string Shared(const BIGNUM* scalar, const std::string& publicKey) const {
    auto point = DecodePoint(publicKey);
    Require(EC_POINT_mul(group.get(), point.get(), NULL, point.get(), scalar, ctx.get()) == 1,
            "shared contribution multiplication failed");
    return EncodePoint(point.get());
  }
  Number PrivateKey(const KeyPair& key, const std::string& selected) const {
    Require(key.publicKey == selected, "private key does not belong to selected member");
    auto scalar = Scalar(key.secret);
    Require(Public(scalar.get()) == selected, "public and private keys do not match");
    return scalar;
  }
};
size_t Count(const std::string& selection, const Curve& curve) {
  Require(!selection.empty() && selection.size() % 64 == 0, "malformed selection length");
  const size_t n = selection.size() / 64;
  SelectionSize(n);
  std::set<std::string> seen;
  for (size_t i = 0; i < n; ++i) {
    const std::string key = selection.substr(i * 64, 64);
    curve.DecodePoint(key);
    Require(seen.insert(key).second, "duplicate selected key");
  }
  return n;
}
std::string RandomBytes(size_t n) {
  Require(n <= static_cast<size_t>(std::numeric_limits<int>::max()), "random byte request too large");
  std::string bytes(n, '\0');
  Require(RAND_bytes(reinterpret_cast<unsigned char*>(&bytes[0]), static_cast<int>(n)) == 1,
          "OpenSSL RNG failed");
  return bytes;
}
std::string Encrypt(const std::string& key, const std::string& plain) {
  Require(key.size() == 32 && plain.size() <= 3360, "invalid encryption input");
  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  Require(static_cast<bool>(context), "cipher allocation failed");
  const std::string nonce = RandomBytes(12);
  std::string cipher(plain.size() + 16, '\0');
  int count = 0, final = 0;
  Require(EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
          EVP_EncryptInit_ex(context.get(), NULL, NULL,
              reinterpret_cast<const unsigned char*>(key.data()),
              reinterpret_cast<const unsigned char*>(nonce.data())) == 1, "AES-GCM initialization failed");
  Require(EVP_EncryptUpdate(context.get(), reinterpret_cast<unsigned char*>(&cipher[0]), &count,
              reinterpret_cast<const unsigned char*>(plain.data()), static_cast<int>(plain.size())) == 1 &&
          EVP_EncryptFinal_ex(context.get(), reinterpret_cast<unsigned char*>(&cipher[0]) + count, &final) == 1,
          "AES-GCM encryption failed");
  cipher.resize(static_cast<size_t>(count + final));
  std::string tag(16, '\0');
  Require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, 16, &tag[0]) == 1,
          "AES-GCM tag failed");
  return nonce + cipher + tag;
}
Secret Decrypt(const std::string& key, const std::string& envelope) {
  Require(key.size() == 32 && envelope.size() >= 28 && envelope.size() <= 3388,
          "invalid encrypted material length");
  const size_t length = envelope.size() - 28;
  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  Require(static_cast<bool>(context), "cipher allocation failed");
  Secret plain(std::string(length + 16, '\0'));
  int count = 0, final = 0;
  Require(EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
          EVP_DecryptInit_ex(context.get(), NULL, NULL,
              reinterpret_cast<const unsigned char*>(key.data()),
              reinterpret_cast<const unsigned char*>(envelope.data())) == 1, "AES-GCM initialization failed");
  Require(EVP_DecryptUpdate(context.get(), reinterpret_cast<unsigned char*>(&plain.value[0]), &count,
              reinterpret_cast<const unsigned char*>(envelope.data() + 12), static_cast<int>(length)) == 1,
          "AES-GCM decryption failed");
  Require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, 16,
              const_cast<char*>(envelope.data() + 12 + length)) == 1, "AES-GCM tag setup failed");
  Require(EVP_DecryptFinal_ex(context.get(), reinterpret_cast<unsigned char*>(&plain.value[0]) + count, &final) == 1,
          "AES-GCM authentication failed");
  plain.value.resize(static_cast<size_t>(count + final));
  return plain;
}
void Verify(const std::string& material, const std::string& selection, uint32_t initiator,
            size_t n, const Curve& curve) {
  Require(initiator < n && material.size() == MaterialSize(n), "malformed material length or initiator");
  const std::string publicKey = selection.substr(initiator * 64, 64);
  Require(material.compare(0, 64, publicKey) == 0 && material.compare(64, selection.size(), selection) == 0,
          "material does not match committed selection");
  curve.DecodePoint(material.substr(64 + selection.size(), 64));
  auto r = curve.DecodePoint(material.substr(material.size() - 96, 64));
  auto a = DecodeNumber(material.substr(material.size() - 32, 32));
  Require(BN_cmp(a.get(), curve.order.get()) < 0, "proof scalar outside Zq");
  const std::string challenge = material.substr(0, material.size() - 32); // pkX || M || R
  auto h = curve.H1({&challenge});
  auto left = curve.NewPoint(); auto right = curve.DecodePoint(publicKey);
  Require(EC_POINT_mul(curve.group.get(), left.get(), a.get(), NULL, NULL, curve.ctx.get()) == 1 &&
          EC_POINT_mul(curve.group.get(), right.get(), NULL, right.get(), h.get(), curve.ctx.get()) == 1 &&
          EC_POINT_add(curve.group.get(), right.get(), r.get(), right.get(), curve.ctx.get()) == 1,
          "proof verification operation failed");
  Require(EC_POINT_cmp(curve.group.get(), left.get(), right.get(), curve.ctx.get()) == 0,
          "invalid initiator proof");
}
Number SumModulus() {
  auto modulus = NewNumber();
  Require(BN_one(modulus.get()) == 1 && BN_lshift(modulus.get(), modulus.get(), 256) == 1,
          "contribution modulus failed");
  return modulus;
}
} // namespace

size_t SelectionSize(size_t n) {
  Require(n >= 1 && n <= 50, "member count must be in [1,50]");
  return 64 * n;
}
size_t MaterialSize(size_t n) {
  SelectionSize(n); // Bound n before multiplication, including hostile size_t values.
  return 64 * n * n + 160 * n + 64 + 28 * (n - 1);
}
std::string RandomSeed() { return RandomBytes(32); }
std::vector<KeyPair> DeriveKeys(const std::string& seed, uint32_t rounds) {
  Require(!seed.empty() && rounds <= 10000, "invalid seed or excessive key count");
  Curve curve;
  auto secret = curve.H1({&seed});
  Secret derivation(Hash(4, {&seed}));
  std::vector<KeyPair> keys; keys.reserve(rounds);
  for (uint64_t k = 1; k <= rounds; ++k) {
    std::string index(8, '\0');
    for (size_t i = 0; i < 8; ++i) index[7 - i] = static_cast<char>((k >> (8 * i)) & 0xff);
    auto factor = curve.H1({&derivation.value, &index});
    Require(BN_mod_mul(secret.get(), factor.get(), secret.get(), curve.order.get(), curve.ctx.get()) == 1,
            "KeyDri multiplication failed");
    Secret next(Hash(4, {&derivation.value, &index}));
    derivation = std::move(next);
    KeyPair key;
    key.secret = EncodeNumber(secret.get()); key.publicKey = curve.Public(secret.get());
    keys.push_back(std::move(key));
  }
  return keys;
}
std::string Selection(const std::vector<std::string>& publicKeys) {
  const size_t bytes = SelectionSize(publicKeys.size());
  std::string selection; selection.reserve(bytes);
  for (const auto& key : publicKeys) {
    Require(key.size() == 64, "selected key must be 64 bytes");
    selection += key;
  }
  Curve curve; Count(selection, curve);
  return selection;
}
Issued Issue(uint32_t initiator, const KeyPair& key, const std::string& selection) {
  Curve curve;
  const size_t n = Count(selection, curve);
  Require(initiator < n, "invalid initiator");
  auto secret = curve.PrivateKey(key, selection.substr(initiator * 64, 64));
  auto z = curve.RandomScalar(); auto gammaScalar = curve.RandomScalar();
  Secret gamma(EncodeNumber(gammaScalar.get()));
  auto total = NewNumber(); auto modulus = SumModulus();
  BN_zero(total.get());
  std::vector<Secret> contributions; contributions.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    Secret shared(curve.Shared(secret.get(), selection.substr(i * 64, 64)));
    contributions.emplace_back(Hash(2, {&shared.value}));
    auto contribution = DecodeNumber(contributions.back().value);
    Require(BN_mod_add(total.get(), total.get(), contribution.get(), modulus.get(), curve.ctx.get()) == 1,
            "contribution sum failed");
  }
  Issued issued;
  issued.material.reserve(MaterialSize(n));
  issued.material = key.publicKey + selection + curve.Public(z.get());
  for (size_t i = 0; i < n; ++i) if (i != initiator) {
    const std::string publicKey = selection.substr(i * 64, 64);
    auto contribution = DecodeNumber(contributions[i].value); auto partial = NewNumber();
    Require(BN_mod_sub(partial.get(), total.get(), contribution.get(), modulus.get(), curve.ctx.get()) == 1,
            "partial contribution failed");
    Secret partialBytes(EncodeNumber(partial.get()));
    Secret wrappingSecret(curve.Shared(z.get(), publicKey));
    Secret kappa(Hash(5, {&wrappingSecret.value}));
    Secret wrappingKey(Hash(3, {&wrappingSecret.value}));
    Secret plain; plain.value.reserve(160 + selection.size());
    plain.value.append(partialBytes.value).append(gamma.value).append(kappa.value).append(publicKey).append(selection);
    issued.material += Encrypt(wrappingKey.value, plain.value);
  }
  auto r = curve.RandomScalar();
  const std::string rPoint = curve.Public(r.get());
  auto h = curve.H1({&issued.material, &rPoint});
  auto a = NewNumber();
  Require(BN_mod_mul(a.get(), h.get(), secret.get(), curve.order.get(), curve.ctx.get()) == 1 &&
          BN_mod_add(a.get(), a.get(), r.get(), curve.order.get(), curve.ctx.get()) == 1,
          "initiator proof generation failed");
  issued.material += rPoint + EncodeNumber(a.get());
  Require(issued.material.size() == MaterialSize(n), "internal material size mismatch");
  Secret totalBytes(EncodeNumber(total.get()));
  issued.key = Hash(3, {&totalBytes.value, &gamma.value, &selection});
  return issued;
}
bool ValidateMaterial(const std::string& material, const std::string& selection, uint32_t initiator) {
  try {
    Curve curve; const size_t n = Count(selection, curve);
    Verify(material, selection, initiator, n, curve);
    return true;
  } catch (const std::exception&) { return false; }
}
std::string Derive(uint32_t node, uint32_t initiator, const KeyPair& key,
                   const std::string& selection, const std::string& material) {
  Curve curve;
  const size_t n = Count(selection, curve);
  Require(node < n && node != initiator, "invalid responder");
  Verify(material, selection, initiator, n, curve);
  auto secret = curve.PrivateKey(key, selection.substr(node * 64, 64));
  Secret wrappingSecret(curve.Shared(secret.get(), material.substr(64 + selection.size(), 64)));
  Secret kappa(Hash(5, {&wrappingSecret.value}));
  Secret wrappingKey(Hash(3, {&wrappingSecret.value}));
  const size_t index = node < initiator ? node : node - 1;
  const size_t envelopeSize = 188 + selection.size();
  const size_t offset = 128 + selection.size() + index * envelopeSize;
  Secret plain = Decrypt(wrappingKey.value, material.substr(offset, envelopeSize));
  Require(plain.value.size() == 160 + selection.size(), "invalid decrypted material length");
  Require(CRYPTO_memcmp(plain.value.data() + 64, kappa.value.data(), 32) == 0 &&
          plain.value.compare(96, 64, key.publicKey) == 0 &&
          plain.value.compare(160, selection.size(), selection) == 0,
          "decrypted kappa, member key or roster does not match selection");
  Secret partialBytes(plain.value.substr(0, 32));
  Secret gamma(plain.value.substr(32, 32));
  curve.Scalar(gamma.value); // The issuer chooses gamma in Zq*.
  Secret shared(curve.Shared(secret.get(), material.substr(0, 64)));
  Secret contribution(Hash(2, {&shared.value}));
  auto total = DecodeNumber(partialBytes.value); auto hashed = DecodeNumber(contribution.value);
  auto modulus = SumModulus();
  Require(BN_mod_add(total.get(), total.get(), hashed.get(), modulus.get(), curve.ctx.get()) == 1,
          "group contribution recovery failed");
  Secret totalBytes(EncodeNumber(total.get()));
  return Hash(3, {&totalBytes.value, &gamma.value, &selection});
}
std::string Digest(const std::string& key) {
  unsigned char digest[32];
  Require(SHA256(reinterpret_cast<const unsigned char*>(key.data()), key.size(), digest) != NULL,
          "key digest failed");
  const char* hex = "0123456789abcdef";
  std::string result; result.reserve(64);
  for (unsigned char byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
  OPENSSL_cleanse(digest, sizeof(digest));
  return result;
}
} // namespace gka
