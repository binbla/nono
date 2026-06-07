#ifndef NOISE_HPP
#define NOISE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "crypto.hpp"
#include "types.hpp"

// noise的高级封装。
// 将密码学原语抽象到mix_xx函数
namespace wg::noise {

// ============================================================================
// Noise constants
// ============================================================================
//
// 这一层只定义固定协议字符串，不保存任何运行期状态。
// base_chaining_key / base_hash 由 NoiseProtocol 初始化后保存。

inline constexpr char kNoiseConstruction[] =
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";  // 37 bytes
inline constexpr char kNoiseIdentifier[] =
    "Supercalifragilisticexpialidocious binbla";  // 41 bytes

// ============================================================================
// Base initialization
// ============================================================================

/// 初始化 Noise 基础状态。
///
/// 语义：
///   base_chaining_key = HASH(kNoiseConstruction)
///   base_hash         = HASH(base_chaining_key || kNoiseIdentifier)
///   base_hash_self    = HASH(base_hash || local_static)
///
/// NoiseProtocol 可以在初始化时调用一次，并缓存输出。
bool initialize_base(ChainingKey& base_chaining_key, Hash& base_hash,
                     Hash& base_hash_self, PublicKey local_public);

// ============================================================================
// Transcript hash
// ============================================================================

/// 更新 Noise transcript hash。
///
/// 语义：
///   hash = HASH(hash || data)
bool mix_hash(Hash& hash, std::span<const uint8_t> data);

/// 便利重载：混入固定大小字节数组。
template <size_t N>
bool mix_hash(Hash& hash, const std::array<uint8_t, N>& data) {
    return mix_hash(hash, std::span<const uint8_t>(data.data(), data.size()));
}

/// 便利重载：混入 public key。
inline bool mix_hash(Hash& hash, const PublicKey& public_key) {
    return mix_hash(
        hash, std::span<const uint8_t>(public_key.data(), public_key.size()));
}

// ============================================================================
// Chaining key
// ============================================================================

/// 更新 chaining key。
///
/// 语义：
///   chaining_key = KDF1(chaining_key, input)
///
/// 用于只需要推进 chaining_key，但不需要输出 AEAD key 的场景。
void mix_key(ChainingKey& chaining_key, std::span<const uint8_t> input);

/// 更新 chaining key，并输出临时 AEAD key。
///
/// 语义：
///   chaining_key, key = KDF2(chaining_key, input)
///
/// 用于 es / ss / ee / se 等 DH 结果混入。
void mix_key(ChainingKey& chaining_key, SymmetricKey& key,
             std::span<const uint8_t> input);

// ============================================================================
// DH mixing
// ============================================================================

/// 执行 DH 并混入 chaining key。
///
/// 语义：
///   shared_secret = DH(private_key, public_key)
///   chaining_key, key = KDF2(chaining_key, shared_secret)
///
/// 返回 false 表示 DH 失败，例如无效公钥或 all-zero shared secret。
bool mix_dh(ChainingKey& chaining_key, SymmetricKey& key,
            const PrivateKey& private_key, const PublicKey& public_key);

/// 将预计算的 static-static DH 结果混入 chaining key。
///
/// 这里不会重新计算 DH。
///
/// 语义：
///   chaining_key, key = KDF2(chaining_key, precomputed_secret)
///
/// 返回 false 表示 precomputed_secret 非法，例如全 0。
bool mix_precomputed_dh(ChainingKey& chaining_key, SymmetricKey& key,
                        const SharedSecret& precomputed_secret);

// ============================================================================
// Ephemeral step
// ============================================================================

/// 处理 Noise 消息里的 e 步。
///
/// 语义：
///   chaining_key = KDF1(chaining_key, ephemeral_public)
///   hash         = HASH(hash || ephemeral_public)
///
/// 注意：
///   这个函数不负责生成 ephemeral keypair，
///   也不负责把 ephemeral_public 写进消息结构体。
void mix_ephemeral(const PublicKey& ephemeral_public, ChainingKey& chaining_key,
                   Hash& hash);

// ============================================================================
// EncryptAndHash / DecryptAndHash
// ============================================================================

/// Noise EncryptAndHash。
///
/// 语义：
///   ciphertext = AEAD(key, nonce = 0, ad = hash, plaintext)
///   hash       = HASH(hash || ciphertext)
///
/// 约束：
///   ciphertext.size() == plaintext.size() + TAG_SIZE
///
/// 注意：
///   只有加密成功后才更新 hash。
bool encrypt_and_hash(std::span<uint8_t> ciphertext,
                      std::span<const uint8_t> plaintext,
                      const SymmetricKey& key, Hash& hash);

/// Noise DecryptAndHash。
///
/// 语义：
///   plaintext = AEAD-Decrypt(key, nonce = 0, ad = hash, ciphertext)
///   hash      = HASH(hash || ciphertext)
///
/// 约束：
///   ciphertext.size() == plaintext.size() + TAG_SIZE
///
/// 注意：
///   只有解密认证成功后才更新 hash。
bool decrypt_and_hash(std::span<uint8_t> plaintext,
                      std::span<const uint8_t> ciphertext,
                      const SymmetricKey& key, Hash& hash);

/// 固定数组版本：EncryptAndHash。
template <size_t CipherSize, size_t PlainSize>
bool encrypt_and_hash(std::array<uint8_t, CipherSize>& ciphertext,
                      const std::array<uint8_t, PlainSize>& plaintext,
                      const SymmetricKey& key, Hash& hash) {
    static_assert(CipherSize == PlainSize + TAG_SIZE,
                  "Noise ciphertext size must be plaintext size + TAG_SIZE");

    return encrypt_and_hash(
        std::span<uint8_t>(ciphertext.data(), ciphertext.size()),
        std::span<const uint8_t>(plaintext.data(), plaintext.size()), key,
        hash);
}

/// 固定数组版本：DecryptAndHash。
template <size_t PlainSize, size_t CipherSize>
bool decrypt_and_hash(std::array<uint8_t, PlainSize>& plaintext,
                      const std::array<uint8_t, CipherSize>& ciphertext,
                      const SymmetricKey& key, Hash& hash) {
    static_assert(CipherSize == PlainSize + TAG_SIZE,
                  "Noise ciphertext size must be plaintext size + TAG_SIZE");

    return decrypt_and_hash(
        std::span<uint8_t>(plaintext.data(), plaintext.size()),
        std::span<const uint8_t>(ciphertext.data(), ciphertext.size()), key,
        hash);
}

// ============================================================================
// PSK mixing
// ============================================================================
//
// WireGuard 使用 IKpsk2，因此 response 阶段需要混入 preshared key。
// 如果你的协议暂时不启用 PSK，也可以传入全 0 PSK，保持流程一致。

/// 混入 preshared key。
///
/// WireGuard IKpsk2 语义：
///   chaining_key, temp_hash, key = KDF3(chaining_key, psk)
///   hash = HASH(hash || temp_hash)
///
/// @param chaining_key 当前 chaining key，函数内原地更新
/// @param hash         当前 transcript hash，函数内原地更新
/// @param key          输出 AEAD key
/// @param psk          preshared key
void mix_psk(ChainingKey& chaining_key, Hash& hash, SymmetricKey& key,
             const PreSharedKey& psk);

// ============================================================================
// Transport key derivation
// ============================================================================

/// 从握手完成后的 chaining_key 派生两个 transport keys。
///
/// 语义：
///   chaining_key, key1, key2 = KDF3(chaining_key, empty)
///
/// WireGuard 方向约定通常是：
///   initiator:
///       send = key1
///       recv = key2
///   responder:
///       send = key2
///       recv = key1
///
/// 该函数只派生 key1/key2，不决定方向。
void derive_transport_keys(ChainingKey& chaining_key, SymmetricKey& key1,
                           SymmetricKey& key2);
}  // namespace wg::noise

#endif  // NOISE_HPP
