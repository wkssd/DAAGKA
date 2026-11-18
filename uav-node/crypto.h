#ifndef IOT_GKA_CRYPTO_H
#define IOT_GKA_CRYPTO_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace gka {
// All wire fields are fixed-width raw bytes: scalars 32, points x32 || y32.
// Secrets are owned by the caller; Peer erases a consumed round's private key.
void Erase(std::string& value);
struct KeyPair {
  std::string secret, publicKey;
  KeyPair() = default;
  KeyPair(const KeyPair&) = default;
  KeyPair& operator=(const KeyPair& other);
  KeyPair(KeyPair&& other) noexcept;
  KeyPair& operator=(KeyPair&& other) noexcept;
  ~KeyPair();
};
struct Issued {
  std::string material, key;
  Issued() = default;
  Issued(const Issued&) = default;
  Issued& operator=(const Issued& other);
  Issued(Issued&& other) noexcept;
  Issued& operator=(Issued&& other) noexcept;
  ~Issued();
};
std::vector<KeyPair> DeriveKeys(const std::string& seed, uint32_t rounds);
std::string RandomSeed();
std::string Selection(const std::vector<std::string>& publicKeys);
size_t SelectionSize(size_t n);
size_t MaterialSize(size_t n);
Issued Issue(uint32_t initiator, const KeyPair& key, const std::string& selection);
bool ValidateMaterial(const std::string& material, const std::string& selection, uint32_t initiator);
// Responders derive from their own locally applied bytes. The initiator instead
// retains Issue's key and checks that the exact cached material was applied.
std::string Derive(uint32_t node, uint32_t initiator, const KeyPair& key,
                   const std::string& selection, const std::string& material);
std::string Digest(const std::string& key);
}
#endif
