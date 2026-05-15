#include "crypto.hpp"

#include <sodium.h>

#include <atomic>
#include <cstring>
#include <mutex>

#include "../external/BLAKE2/sse/blake2.h"
#include "utils.hpp"

namespace wg::crypto {
// ===================== helper =====================
namespace {
std::once_flag g_crypto_init_once;
std::atomic_bool g_crypto_initialized{false};
const unsigned char* ptr_or_null(std::span<const uint8_t> s) noexcept {
    return s.empty() ? nullptr : s.data();
}

unsigned char* ptr_or_null(std::span<uint8_t> s) noexcept {
    return s.empty() ? nullptr : s.data();
}

void clamp_x25519_private_key(PrivateKey& priv) {
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
}

}  // namespace
bool init() {
    std::call_once(g_crypto_init_once, [] {
        if (sodium_init() >= 0) {
            g_crypto_initialized.store(true, std::memory_order_release);
        }
    });

    return g_crypto_initialized.load(std::memory_order_acquire);
}

bool is_initialized() {
    return g_crypto_initialized.load(std::memory_order_acquire);
}
void secure_zero(std::span<uint8_t> data) {
    if (!data.empty()) {
        sodium_memzero(data.data(), data.size());
    }
}

bool constant_time_equal(std::span<const uint8_t> a,
                         std::span<const uint8_t> b) {
    if (a.size() != b.size()) {
        return false;
    }
    uint8_t acc = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        acc |= a[i] ^ b[i];
    }
    return acc == 0;
}
bool is_all_zero(std::span<const uint8_t> data) {
    uint8_t acc = 0;
    for (uint8_t b : data) {
        acc |= b;
    }
    return acc == 0;
}
// ===================== random =====================
bool random_bytes(std::span<uint8_t> out) {
    if (out.empty()) {
        return true;
    }

    randombytes_buf(out.data(), out.size());
    return true;
}

// ===================== key =====================
bool generate_static_keypair(PrivateKey& priv, PublicKey& pub) {
    if (!fill_random(priv)) {
        priv.fill(0);
        pub.fill(0);
        return false;
    }
    clamp_x25519_private_key(priv);
    if (!derive_public_key(priv, pub)) {
        priv.fill(0);
        pub.fill(0);
        return false;
    }
    return true;
}
bool derive_public_key(const PrivateKey& priv, PublicKey& pub) {
    crypto_scalarmult_base(pub.data(), priv.data());
    return true;
}
bool generate_ephemeral_keypair(PrivateKey& priv, PublicKey& pub) {
    return generate_static_keypair(priv, pub);
}

// ===================== DH =====================
bool dh(const PrivateKey& priv, const PublicKey& pub, SharedSecret& out) {
    if (crypto_scalarmult(out.data(), priv.data(), pub.data()) != 0) {
        out.fill(0);
        return false;
    }
    if (is_all_zero(out)) {
        out.fill(0);
        return false;
    }
    return true;
}

// ===================== AEAD =====================
bool aead_encrypt_detached(const SymmetricKey& key, const Nonce& nonce,
                           std::span<const uint8_t> ad,
                           std::span<const uint8_t> plaintext,
                           std::span<uint8_t> ciphertext, Tag& tag) {
    if (ciphertext.size() != plaintext.size()) {
        return false;
    }

    unsigned long long tag_len = 0;
    const int rc = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        ptr_or_null(ciphertext), tag.data(), &tag_len, ptr_or_null(plaintext),
        static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
        static_cast<unsigned long long>(ad.size()),
        nullptr,  // nsec, unused
        nonce.data(), key.data());

    if (rc != 0) {
        return false;
    }
    return tag_len == TAG_SIZE;
}

bool aead_decrypt_detached(const SymmetricKey& key, const Nonce& nonce,
                           std::span<const uint8_t> ad,
                           std::span<const uint8_t> ciphertext, const Tag& tag,
                           std::span<uint8_t> plaintext) {
    if (plaintext.size() != ciphertext.size()) {
        return false;
    }

    const int rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        ptr_or_null(plaintext),
        nullptr,  // nsec, unused
        ptr_or_null(ciphertext),
        static_cast<unsigned long long>(ciphertext.size()), tag.data(),
        ptr_or_null(ad), static_cast<unsigned long long>(ad.size()),
        nonce.data(), key.data());
    if (rc != 0) {
        secure_zero(plaintext);
        return false;
    }
    return true;
}

bool aead_encrypt(const SymmetricKey& key, const Nonce& nonce,
                  std::span<const uint8_t> ad,
                  std::span<const uint8_t> plaintext,
                  std::span<uint8_t> ciphertext) {
    if (ciphertext.size() != plaintext.size() + TAG_SIZE) {
        return false;
    }

    unsigned long long ciphertext_len = 0;
    const int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        ptr_or_null(ciphertext), &ciphertext_len, ptr_or_null(plaintext),
        static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
        static_cast<unsigned long long>(ad.size()),
        nullptr,  // nsec, unused
        nonce.data(), key.data());
    if (rc != 0) {
        return false;
    }
    return ciphertext_len == ciphertext.size();
}

bool aead_decrypt(const SymmetricKey& key, const Nonce& nonce,
                  std::span<const uint8_t> ad,
                  std::span<const uint8_t> ciphertext,
                  std::span<uint8_t> plaintext) {
    if (ciphertext.size() < TAG_SIZE ||
        plaintext.size() != ciphertext.size() - TAG_SIZE) {
        return false;
    }

    unsigned long long plaintext_len = 0;
    const int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        ptr_or_null(plaintext), &plaintext_len,
        nullptr,  // nsec, unused
        ptr_or_null(ciphertext),
        static_cast<unsigned long long>(ciphertext.size()), ptr_or_null(ad),
        static_cast<unsigned long long>(ad.size()), nonce.data(), key.data());
    if (rc != 0) {
        secure_zero(plaintext);
        return false;
    }
    return plaintext_len == plaintext.size();
}
// ===================== XAEAD =====================
bool xaead_encrypt_detached(const SymmetricKey& key, const XNonce& nonce,
                            std::span<const uint8_t> ad,
                            std::span<const uint8_t> plaintext,
                            std::span<uint8_t> ciphertext, Tag& tag) {
    if (ciphertext.size() != plaintext.size()) {
        return false;
    }

    unsigned long long mac_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        ptr_or_null(ciphertext), tag.data(), &mac_len, ptr_or_null(plaintext),
        static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
        static_cast<unsigned long long>(ad.size()),
        nullptr,  // nsec, unused
        nonce.data(), key.data());

    if (rc != 0) {
        return false;
    }
    return mac_len == TAG_SIZE;
}
bool xaead_decrypt_detached(const SymmetricKey& key, const XNonce& nonce,
                            std::span<const uint8_t> ad,
                            std::span<const uint8_t> ciphertext, const Tag& tag,
                            std::span<uint8_t> plaintext) {
    if (plaintext.size() != ciphertext.size()) {
        return false;
    }
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        ptr_or_null(plaintext),
        nullptr,  // nsec, unused
        ptr_or_null(ciphertext),
        static_cast<unsigned long long>(ciphertext.size()), tag.data(),
        ptr_or_null(ad), static_cast<unsigned long long>(ad.size()),
        nonce.data(), key.data());
    if (rc != 0) {
        secure_zero(plaintext);
        return false;
    }
    return true;
}
bool xaead_encrypt(const SymmetricKey& key, const XNonce& nonce,
                   std::span<const uint8_t> ad,
                   std::span<const uint8_t> plaintext,
                   std::span<uint8_t> ciphertext) {
    if (ciphertext.size() != plaintext.size() + TAG_SIZE) {
        return false;
    }

    unsigned long long ciphertext_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ptr_or_null(ciphertext), &ciphertext_len, ptr_or_null(plaintext),
        static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
        static_cast<unsigned long long>(ad.size()),
        nullptr,  // nsec, unused
        nonce.data(), key.data());
    if (rc != 0) {
        return false;
    }

    return ciphertext_len == ciphertext.size();
}
bool xaead_decrypt(const SymmetricKey& key, const XNonce& nonce,
                   std::span<const uint8_t> ad,
                   std::span<const uint8_t> ciphertext,
                   std::span<uint8_t> plaintext) {
    if (ciphertext.size() < TAG_SIZE ||
        plaintext.size() != ciphertext.size() - TAG_SIZE) {
        return false;
    }

    unsigned long long plaintext_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ptr_or_null(plaintext), &plaintext_len,
        nullptr,  // nsec, unused
        ptr_or_null(ciphertext),
        static_cast<unsigned long long>(ciphertext.size()), ptr_or_null(ad),
        static_cast<unsigned long long>(ad.size()), nonce.data(), key.data());
    if (rc != 0) {
        secure_zero(plaintext);
        return false;
    }
    return plaintext_len == plaintext.size();
}
// ===================== Hash =====================
inline int blake2s_span(std::span<const uint8_t> in,   // 不固定输入
                        std::span<const uint8_t> key,  // 不固定输入
                        std::span<uint8_t> out) {      // 输出
    return blake2s(out.data(), out.size(), ptr_or_null(in), in.size(),
                   ptr_or_null(key), key.size());
}
// 完全信任输入
bool hash(std::span<const uint8_t> data, Hash& out) {
    const int rc = blake2s_span(data, {}, out);
    return rc == 0;
}
// 完全信任输入
bool hash_concat(std::span<const uint8_t> a, std::span<const uint8_t> b,
                 Hash& out) {
    // 直接调用底层的 blake2s_state 来避免中间缓冲区
    blake2s_state blake{};
    blake2s_init(&blake, out.size());
    blake2s_update(&blake, a.data(), a.size());
    blake2s_update(&blake, b.data(), b.size());
    blake2s_final(&blake, out.data(), out.size());
    return true;
}
bool mac(std::span<const uint8_t> data, std::span<const uint8_t> key,
         Mac& out) {
    // Keyed BLAKE2s
    // 带上密钥的情况下输出 16 字节的 hash
    const int rc = blake2s_span(data, key, out);
    return rc == 0;
}
// ===================== HMAC =====================
bool hmac(std::span<const uint8_t> data, std::span<const uint8_t> key,
          std::span<uint8_t, HMAC_SIZE> out) {
    std::array<uint8_t, BLOCK_SIZE> k0{};
    std::array<uint8_t, BLOCK_SIZE> ipad{};
    std::array<uint8_t, BLOCK_SIZE> opad{};
    std::array<uint8_t, HASH_SIZE> inner_hash{};

    // 1. Normalize key
    if (key.size() > BLOCK_SIZE) {
        blake2s(k0.data(), HASH_SIZE, key.data(), key.size(), nullptr, 0);
    } else {
        std::memcpy(k0.data(), key.data(), key.size());
    }

    // 2. Compute ipad and opad
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        ipad[i] = static_cast<uint8_t>(k0[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k0[i] ^ 0x5c);
    }

    // 3. Inner hash: H((K ⊕ ipad) || data)
    blake2s_state st{};
    blake2s_init(&st, HASH_SIZE);
    blake2s_update(&st, ipad.data(), ipad.size());
    blake2s_update(&st, data.data(), data.size());
    blake2s_final(&st, inner_hash.data(), inner_hash.size());

    // 4. Outer hash: H((K ⊕ opad) || inner_hash)
    blake2s_init(&st, HASH_SIZE);
    blake2s_update(&st, opad.data(), opad.size());
    blake2s_update(&st, inner_hash.data(), inner_hash.size());
    blake2s_final(&st, out.data(), out.size());

    // 5. clear sensitive memory (just for security)
    secure_zero(k0);
    secure_zero(ipad);
    secure_zero(opad);
    secure_zero(inner_hash);
    sodium_memzero(&st, sizeof(st));

    return true;
}

// ===================== KDF ======================
void kdf1(const ChainingKey& chaining_key, std::span<const uint8_t> data,
          ChainingKey& out1) {
    std::array<uint8_t, HMAC_SIZE> secret{};
    std::array<uint8_t, HMAC_SIZE + 1> output{};

    // Extract: secret = HMAC(chaining_key, data)
    hmac(data, chaining_key,
         std::span<uint8_t, HMAC_SIZE>(secret.data(), HMAC_SIZE));

    // Expand first key: HMAC(secret, 0x01)
    output[0] = 1;
    hmac(std::span<const uint8_t>(output.data(), 1), secret,
         std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));

    std::memcpy(out1.data(), output.data(), out1.size());
    // Clear sensitive data
    secure_zero(secret);
    secure_zero(output);
}

void kdf2(const ChainingKey& chaining_key, std::span<const uint8_t> data,
          ChainingKey& out1, SymmetricKey& out2) {
    std::array<uint8_t, HMAC_SIZE> secret{};
    std::array<uint8_t, HMAC_SIZE + 1> output{};

    // Extract: secret = HMAC(chaining_key, data)
    hmac(data, chaining_key,
         std::span<uint8_t, HMAC_SIZE>(secret.data(), HMAC_SIZE));

    // Expand first key: HMAC(secret, 0x01)
    output[0] = 1;
    hmac(std::span<const uint8_t>(output.data(), 1), secret,
         std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
    std::memcpy(out1.data(), output.data(), out1.size());

    // Expand second key: HMAC(secret, first_key || 0x02)
    output[HMAC_SIZE] = 2;
    hmac(std::span<const uint8_t>(output.data(), HMAC_SIZE + 1), secret,
         std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
    std::memcpy(out2.data(), output.data(), out2.size());
    // Clear sensitive data
    secure_zero(secret);
    secure_zero(output);
}

void kdf3(const ChainingKey& chaining_key, std::span<const uint8_t> data,
          ChainingKey& out1, Bytes32& out2, SymmetricKey& out3) {
    std::array<uint8_t, HMAC_SIZE> secret{};
    std::array<uint8_t, HMAC_SIZE + 1> output{};

    // Extract: secret = HMAC(chaining_key, data)
    hmac(data, chaining_key,
         std::span<uint8_t, HMAC_SIZE>(secret.data(), HMAC_SIZE));

    // Expand first key: HMAC(secret, 0x01)
    output[0] = 1;
    hmac(std::span<const uint8_t>(output.data(), 1), secret,
         std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
    std::memcpy(out1.data(), output.data(), out1.size());

    // Expand second key: HMAC(secret, first_key || 0x02)
    output[HMAC_SIZE] = 2;
    hmac(std::span<const uint8_t>(output.data(), HMAC_SIZE + 1), secret,
         std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
    std::memcpy(out2.data(), output.data(), out2.size());

    // Expand third key: HMAC(secret, second_key || 0x03)
    output[HMAC_SIZE] = 3;
    hmac(std::span<const uint8_t>(output.data(), HMAC_SIZE + 1), secret,
         std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
    std::memcpy(out3.data(), output.data(), out3.size());
    // Clear sensitive data
    secure_zero(secret);
    secure_zero(output);
}
// ===================== libsodium size checks =====================
static_assert(SYMMETRIC_KEY_SIZE == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
static_assert(SYMMETRIC_KEY_SIZE ==
              crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

static_assert(NONCE_SIZE == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
static_assert(XNONCE_SIZE == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

static_assert(TAG_SIZE == crypto_aead_chacha20poly1305_ietf_ABYTES);
static_assert(TAG_SIZE == crypto_aead_xchacha20poly1305_ietf_ABYTES);
}  // namespace wg::crypto
