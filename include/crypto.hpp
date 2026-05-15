#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "types.hpp"

// 对密码学原语的封装
namespace wg::crypto {

// ============================================================================
// Constants
// ============================================================================
//
// 这里不重新定义密钥长度，默认使用 types.hpp 中的类型：
// PrivateKey, PublicKey, SharedSecret, SymmetricKey, Nonce, XNonce,
// Tag, Hash, Mac, ChainingKey, Bytes32 等。
//

/// 初始化底层密码学库。
///
/// 使用 libsodium 时，该函数内部调用 sodium_init()。
/// 程序启动后、调用任何 crypto 函数前，应先调用一次。
///
/// @return true 表示初始化成功
bool init();

/// 查询 crypto 库是否已经初始化。
///
/// @return true 表示已经初始化
bool is_initialized();

// crypto 层只提供原始密码学操作，不包含 Noise transcript 语义。
// 例如 mix_hash / mix_key / mix_dh / encrypt_and_hash 不应放在这里。

// ============================================================================
// Key: X25519 key generation and public key derivation
// ============================================================================

/// 生成 X25519 长期静态密钥对。
///
/// 对 WireGuard-like 协议来说，静态密钥和临时密钥在算法层面没有区别，
/// 都是 X25519 keypair。二者的区别只在协议生命周期。
///
/// @param priv 输出私钥
/// @param pub  输出公钥
/// @return true 表示生成成功，false 表示 RNG 或底层实现失败
bool generate_static_keypair(PrivateKey& priv, PublicKey& pub);

/// 生成 X25519 临时密钥对。
///
/// 通常内部可以直接调用 generate_static_keypair()。
///
/// @param priv 输出临时私钥
/// @param pub  输出临时公钥
/// @return true 表示生成成功，false 表示 RNG 或底层实现失败
bool generate_ephemeral_keypair(PrivateKey& priv, PublicKey& pub);

/// 从 X25519 私钥派生公钥。
///
/// @param priv 输入私钥
/// @param pub  输出公钥
/// @return true 表示派生成功
bool derive_public_key(const PrivateKey& priv, PublicKey& pub);

// ============================================================================
// DH: X25519
// ============================================================================

/// 计算 X25519 DH 共享密钥。
///
/// 必须拒绝 all-zero shared secret。对于 X25519，遇到低阶点时可能产生
/// 全 0 输出，这种情况必须返回 false。
///
/// @param priv 本地私钥
/// @param pub  对端公钥
/// @param out  输出 shared secret
/// @return true 表示成功，false 表示无效公钥或 all-zero shared secret
bool dh(const PrivateKey& priv, const PublicKey& pub, SharedSecret& out);

// ============================================================================
// AEAD: ChaCha20-Poly1305
// ============================================================================

/// ChaCha20-Poly1305 detached 加密。
///
/// ciphertext 长度必须等于 plaintext 长度。
///
/// @param key        32 字节对称密钥
/// @param nonce      96-bit nonce
/// @param ad         associated data，只认证不加密
/// @param plaintext  明文
/// @param ciphertext 输出密文，不包含 tag
/// @param tag        输出 Poly1305 tag
/// @return true 表示成功，false 表示参数长度非法或底层失败
bool aead_encrypt_detached(const SymmetricKey& key, const Nonce& nonce,
                           std::span<const uint8_t> ad,
                           std::span<const uint8_t> plaintext,
                           std::span<uint8_t> ciphertext, Tag& tag);

/// ChaCha20-Poly1305 detached 解密。
///
/// ciphertext 长度必须等于 plaintext 长度。
///
/// @param key        32 字节对称密钥
/// @param nonce      96-bit nonce
/// @param ad         associated data，只认证不加密
/// @param ciphertext 密文，不包含 tag
/// @param tag        Poly1305 tag
/// @param plaintext  输出明文
/// @return true 表示认证通过并解密成功，false 表示认证失败或参数非法
bool aead_decrypt_detached(const SymmetricKey& key, const Nonce& nonce,
                           std::span<const uint8_t> ad,
                           std::span<const uint8_t> ciphertext, const Tag& tag,
                           std::span<uint8_t> plaintext);

/// ChaCha20-Poly1305 加密，tag 附加在 ciphertext 末尾。
///
/// ciphertext 长度必须等于 plaintext.size() + Tag.size()。
///
/// @param key        32 字节对称密钥
/// @param nonce      96-bit nonce
/// @param ad         associated data，只认证不加密
/// @param plaintext  明文
/// @param ciphertext 输出密文，末尾附加 16 字节 tag
/// @return true 表示成功
bool aead_encrypt(const SymmetricKey& key, const Nonce& nonce,
                  std::span<const uint8_t> ad,
                  std::span<const uint8_t> plaintext,
                  std::span<uint8_t> ciphertext);

/// ChaCha20-Poly1305 解密，输入 ciphertext 末尾包含 tag。
///
/// plaintext 长度必须等于 ciphertext.size() - Tag.size()。
///
/// @param key        32 字节对称密钥
/// @param nonce      96-bit nonce
/// @param ad         associated data，只认证不加密
/// @param ciphertext 密文，末尾包含 16 字节 tag
/// @param plaintext  输出明文
/// @return true 表示认证通过并解密成功
bool aead_decrypt(const SymmetricKey& key, const Nonce& nonce,
                  std::span<const uint8_t> ad,
                  std::span<const uint8_t> ciphertext,
                  std::span<uint8_t> plaintext);

// ============================================================================
// XAEAD: XChaCha20-Poly1305
// ============================================================================
//
// XChaCha20-Poly1305 不是 WireGuard 标准握手和传输层必需项。
// 如果你的协议暂时只对齐 WireGuard，可以先不实现这组函数。
// 如果保留，用于需要 192-bit nonce 的应用层加密场景。

/// XChaCha20-Poly1305 detached 加密。
///
/// ciphertext 长度必须等于 plaintext 长度。
///
/// @param key        32 字节对称密钥
/// @param nonce      192-bit nonce
/// @param ad         associated data，只认证不加密
/// @param plaintext  明文
/// @param ciphertext 输出密文，不包含 tag
/// @param tag        输出认证 tag
/// @return true 表示成功
bool xaead_encrypt_detached(const SymmetricKey& key, const XNonce& nonce,
                            std::span<const uint8_t> ad,
                            std::span<const uint8_t> plaintext,
                            std::span<uint8_t> ciphertext, Tag& tag);

/// XChaCha20-Poly1305 detached 解密。
///
/// @return true 表示认证通过并解密成功
bool xaead_decrypt_detached(const SymmetricKey& key, const XNonce& nonce,
                            std::span<const uint8_t> ad,
                            std::span<const uint8_t> ciphertext, const Tag& tag,
                            std::span<uint8_t> plaintext);

/// XChaCha20-Poly1305 加密，tag 附加在 ciphertext 末尾。
///
/// ciphertext 长度必须等于 plaintext.size() + Tag.size()。
///
/// @return true 表示成功
bool xaead_encrypt(const SymmetricKey& key, const XNonce& nonce,
                   std::span<const uint8_t> ad,
                   std::span<const uint8_t> plaintext,
                   std::span<uint8_t> ciphertext);

/// XChaCha20-Poly1305 解密，输入 ciphertext 末尾包含 tag。
///
/// plaintext 长度必须等于 ciphertext.size() - Tag.size()。
///
/// @return true 表示认证通过并解密成功
bool xaead_decrypt(const SymmetricKey& key, const XNonce& nonce,
                   std::span<const uint8_t> ad,
                   std::span<const uint8_t> ciphertext,
                   std::span<uint8_t> plaintext);

// ============================================================================
// Hash: BLAKE2s
// ============================================================================

/// BLAKE2s hash。
///
/// WireGuard 使用 BLAKE2s，输出 32 字节。
///
/// @param data 输入数据
/// @param out  输出 32 字节 hash
bool hash(std::span<const uint8_t> data, Hash& out);

/// BLAKE2s hash of concatenation of two inputs。
/// 语义上等价于 hash(a || b)，但实现时可以避免中间缓冲区。
/// @param a   输入数据 a
/// @param b   输入数据 b
/// @param out 输出 32 字节 hash
bool hash_concat(std::span<const uint8_t> a, std::span<const uint8_t> b,
                 Hash& out);

/// BLAKE2s keyed hash / MAC。
///
/// WireGuard 的 mac1/mac2 可以基于 keyed BLAKE2s 实现。
///
/// @param data 输入数据
/// @param key  MAC key
/// @param out  输出 MAC
bool mac(std::span<const uint8_t> data, std::span<const uint8_t> key, Mac& out);

// ============================================================================
// HMAC: HMAC-BLAKE2s style helper
// ============================================================================
//
// WireGuard 的 KDF 实际使用的是基于 BLAKE2s 的 HMAC-like 构造。
// 这里保留 hmac 作为 KDF 的底层 primitive。
// 如果你后续严格复刻 WireGuard，需要确保实现与 WireGuard 的 KDF 兼容。

/// HMAC / keyed hash helper。
///
/// @param data 输入数据
/// @param key  key
/// @param out  输出 HMAC_SIZE 字节结果
bool hmac(std::span<const uint8_t> data, std::span<const uint8_t> key,
          std::span<uint8_t, HMAC_SIZE> out);

// ============================================================================
// KDF
// ============================================================================
//
// 这里的 kdf1/kdf2/kdf3 是底层 KDF 展开函数。
// 它们本身可以留在 crypto 层，因为它们不直接修改 Noise 状态，
// 只是根据 chaining_key 和 input 生成若干输出。
//
// 注意：mix_key / mix_dh / mix_precomputed_dh 应该放到 noise 层，
// 不应该放在 crypto 层。

/// KDF1。
///
/// @param chaining_key 输入 chaining key
/// @param data         输入材料
/// @param out1         输出新的 chaining key
void kdf1(const ChainingKey& chaining_key, std::span<const uint8_t> data,
          ChainingKey& out1);

/// KDF2。
///
/// @param chaining_key 输入 chaining key
/// @param data         输入材料
/// @param out1         输出新的 chaining key
/// @param out2         输出对称密钥
void kdf2(const ChainingKey& chaining_key, std::span<const uint8_t> data,
          ChainingKey& out1, SymmetricKey& out2);

/// KDF3。
///
/// @param chaining_key 输入 chaining key
/// @param data         输入材料
/// @param out1         输出新的 chaining key
/// @param out2         输出中间 32 字节材料
/// @param out3         输出对称密钥
void kdf3(const ChainingKey& chaining_key, std::span<const uint8_t> data,
          ChainingKey& out1, Bytes32& out2, SymmetricKey& out3);

// ============================================================================
// RNG
// ============================================================================

/// 从系统 CSPRNG 读取随机字节。
///
/// @param out 输出 buffer
/// @return true 表示成功，false 表示系统随机源失败
bool random_bytes(std::span<uint8_t> out);

/// 填充固定大小 array。
template <size_t N>
bool fill_random(std::array<uint8_t, N>& arr) {
    return random_bytes(std::span<uint8_t>(arr.data(), arr.size()));
}

// ============================================================================
// Memory hygiene
// ============================================================================

/// 安全清零。
///
/// 用于清理私钥、DH shared secret、中间 AEAD key、chain key 等敏感材料。
/// 实现时不能被编译器优化掉。
void secure_zero(std::span<uint8_t> data);

template <size_t N>
void secure_zero(std::array<uint8_t, N>& arr) {
    secure_zero(std::span<uint8_t>(arr.data(), arr.size()));
}

// ============================================================================
// Constant-time helpers
// ============================================================================

/// 常量时间比较。
///
/// 用于比较 tag、mac、hash 等敏感认证材料。
///
/// @return true 表示两段数据长度相同且内容相同
bool constant_time_equal(std::span<const uint8_t> a,
                         std::span<const uint8_t> b);

/// 判断 buffer 是否全 0。
///
/// dh() 内部应该用它拒绝 X25519 all-zero shared secret。
///
/// @return true 表示全 0
bool is_all_zero(std::span<const uint8_t> data);

}  // namespace wg::crypto

#endif  // CRYPTO_HPP