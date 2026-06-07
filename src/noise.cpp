#include "noise.hpp"

#include "crypto.hpp"
#include "types.hpp"

// 仿造wg实现的Noise协议高级封装
namespace wg::noise {
bool initialize_base(ChainingKey& base_chaining_key, Hash& base_hash,
                     Hash& base_hash_self, PublicKey local_public) {
    // 还得包装一下 常量字符串，转换成span传给crypto层的hash函数
    // 没关系，反正这个函数只调用一次，效率不是问题。
    std::span<const uint8_t> construction_span(
        reinterpret_cast<const uint8_t*>(kNoiseConstruction),
        sizeof(kNoiseConstruction) - 1);
    std::span<const uint8_t> identifier_span(
        reinterpret_cast<const uint8_t*>(kNoiseIdentifier),
        sizeof(kNoiseIdentifier) - 1);
    // C_i
    wg::crypto::hash(construction_span, base_chaining_key);
    // H_i
    wg::crypto::hash_concat(base_chaining_key, identifier_span, base_hash);
    // H_i_self
    wg::crypto::hash_concat(base_hash, local_public, base_hash_self);
    return true;
}

// HASH(hash || data)
bool mix_hash(Hash& hash, std::span<const uint8_t> data) {
    return wg::crypto::hash_concat(hash, data, hash);
}
// KDF1(chaining_key, input) -> chaining_key
void mix_key(ChainingKey& chaining_key, std::span<const uint8_t> input) {
    // 只有kdf1是支持原地更新ck的
    wg::crypto::kdf1(chaining_key, input, chaining_key);
}

// KDF2(chaining_key, input) -> chaining_key, key
void mix_key(ChainingKey& chaining_key, SymmetricKey& key,
             std::span<const uint8_t> input) {
    // kdf2需要临时变量来接收输出，不能原地更新ck
    ChainingKey new_ck{};
    wg::crypto::kdf2(chaining_key, input, new_ck, key);
    chaining_key = new_ck;
    crypto::secure_zero(new_ck);
}

// shared_secret = DH(private_key, public_key)
// chaining_key, key = KDF2(chaining_key, shared_secret)
bool mix_dh(ChainingKey& chaining_key, SymmetricKey& key,
            const PrivateKey& private_key, const PublicKey& public_key) {
    wg::SharedSecret dh_value{};
    if (!wg::crypto::dh(private_key, public_key, dh_value)) {
        return false;
    }
    mix_key(chaining_key, key, dh_value);
    return true;
}

// 这个函数直接输入预计算的 DH 结果，不需要再计算一次了。
// chaining_key, key = KDF2(chaining_key, precomputed_secret)
bool mix_precomputed_dh(ChainingKey& chaining_key, SymmetricKey& key,
                        const SharedSecret& precomputed_secret) {
    if (wg::crypto::is_all_zero(precomputed_secret)) {
        return false;
    }
    mix_key(chaining_key, key, precomputed_secret);
    return true;
}

// Ci := Kdf1(Ci, Epub_i)
// msg.ephemeral := Epub_i
// Hi := Hash(Hi ‖ msg.ephemeral)
void mix_ephemeral(const PublicKey& ephemeral_public, ChainingKey& chaining_key,
                   Hash& hash) {
    // kdf1 是安全的。
    // wg::crypto::kdf1(chaining_key, ephemeral_public, chaining_key);
    mix_key(chaining_key, std::span<const uint8_t>(ephemeral_public.data(),
                                                   ephemeral_public.size()));
    // mix_key(chaining_key, hash, ephemeral_public);
    mix_hash(hash, ephemeral_public);
}

bool encrypt_and_hash(std::span<uint8_t> ciphertext,
                      std::span<const uint8_t> plaintext,
                      const SymmetricKey& key, Hash& hash) {
    if (!wg::crypto::aead_encrypt(key, Nonce{}, hash, plaintext, ciphertext)) {
        return false;
    }
    mix_hash(hash, ciphertext);
    return true;
}
bool decrypt_and_hash(std::span<uint8_t> plaintext,
                      std::span<const uint8_t> ciphertext,
                      const SymmetricKey& key, Hash& hash) {
    //
    if (!wg::crypto::aead_decrypt(key, Nonce{}, hash, ciphertext, plaintext)) {
        return false;
    }
    mix_hash(hash, ciphertext);
    return true;
}

// 这个函数直接输入预计算的 DH 结果，不需要再计算一次了。
void mix_psk(ChainingKey& chaining_key, Hash& hash, SymmetricKey& key,
             const PreSharedKey& psk) {
    ChainingKey new_ck{};
    Bytes32 temp_hash{};
    SymmetricKey new_key{};

    wg::crypto::kdf3(chaining_key, psk, new_ck, temp_hash, new_key);
    chaining_key = new_ck;
    key = new_key;
    mix_hash(hash, temp_hash);
}
void derive_transport_keys(ChainingKey& chaining_key, SymmetricKey& key1,
                           SymmetricKey& key2) {
    wg::crypto::kdf3(chaining_key, std::span<const uint8_t>{}, chaining_key,
                     key1, key2);
    //
}
}  // namespace wg::noise