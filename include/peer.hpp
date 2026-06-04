#ifndef PEER_HPP
#define PEER_HPP

#include <netinet/in.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "endpoint.hpp"
#include "handshake.hpp"
#include "keypair_manager.hpp"
#include "noise.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace wg {
constexpr const char kMac1Label[] = "mac1----";    // 用作预计算
constexpr const char kCookieLabel[] = "cookie--";  // 用作预计算

struct PeerConfig {  // 离线定义一个Peer（名片）
    PublicKey remote_static;
    PreSharedKey preshared_key{};
    std::optional<Endpoint> endpoint;
};

class Peer {
    /*
    代表一个对等体，包含身份信息、握手状态、keypair管理等
        Peer需要掌握的东西：
        - 对端长期公钥（身份）
        - 可选的预共享密钥
        - 预计算的长期静态 DH 结果（precomputed_static_static）
        - 预计算的Noise握手HASH（base_hash）
        - 握手状态（Handshake）
        - keypair 插槽（KeypairManager）
    */

   public:
    explicit Peer(const PeerConfig& config)
        : remote_static_(config.remote_static),
          preshared_key_(config.preshared_key),
          endpoint_(config.endpoint) {
        std::span<const uint8_t> mac1label(
            reinterpret_cast<const uint8_t*>(kMac1Label),
            sizeof(kMac1Label) - 1);
        std::span<const uint8_t> remote_static_span(remote_static_.data(),
                                                    remote_static_.size());
        std::span<const uint8_t> cookie_label_span(
            reinterpret_cast<const uint8_t*>(kCookieLabel),
            sizeof(kCookieLabel) - 1);
        crypto::hash_concat(mac1label, remote_static_span,
                            precomputed_mac1_hash_);
        crypto::hash_concat(cookie_label_span, remote_static_span,
                            precomputed_mac2_hash_);
    }

    // -------- identity / config --------

    const PublicKey& remote_static() const { return remote_static_; }
    const PreSharedKey& preshared_key() const { return preshared_key_; }
    void set_preshared_key(const PreSharedKey& psk) { preshared_key_ = psk; }

    // -------- endpoint --------

    const std::optional<Endpoint>& endpoint() const { return endpoint_; }
    void set_endpoint(const Endpoint& ep) { endpoint_ = ep; }

    // -------- handshake / keypairs --------

    const SharedSecret& precomputed_static_static() const {
        return precomputed_static_static_;
    }
    const Hash& base_hash() const { return base_hash_; }  // mixed pubkey
    void set_precomputed_static_static(const SharedSecret& secret) {
        precomputed_static_static_ = secret;
    }
    bool initialize_crypto_state(const PrivateKey& local_private,
                                 const Hash& protocol_base_hash) {
        if (!crypto::dh(local_private, remote_static_,
                        precomputed_static_static_)) {
            return false;
        }
        return noise::initialize_handshake_from_base(protocol_base_hash,
                                                     remote_static_,
                                                     base_hash_);
    }
    const Hash& precomputed_mac1_hash() const { return precomputed_mac1_hash_; }
    const Hash& precomputed_mac2_hash() const { return precomputed_mac2_hash_; }

    Handshake& handshake() { return handshake_; }  // 返回的是引用，方便外部修改
    KeypairManager& keypairs() { return keypairs_; }

   private:
    // peer 的长期身份信息 自己存一个
    PublicKey remote_static_{};
    PreSharedKey preshared_key_{};
    std::optional<Endpoint> endpoint_;

    // 三个预计算材料
    // 与 peer 绑定的长期预计算缓存也就是secret
    SharedSecret precomputed_static_static_{};
    // HASH(H_{init} || S^{pub}_r)，也就是base_hash
    Hash base_hash_{};
    // 预计算 mac1 的 key 派生输入，等价于 HASH("mac1----" || S^{pub}_r)
    Hash precomputed_mac1_hash_{};
    // 预计算 mac2 的 key 派生输入，等价于 HASH("cookie--" || S^{pub}_r)
    Hash precomputed_mac2_hash_{};

    // 运行时状态 Handshake 和 KeypairManager
    Handshake handshake_;  // 静态分配空间，避免后续频繁new/delete

    KeypairManager keypairs_;  // 三槽

    // ===== keepalive =====
    uint16_t keepalive_interval = 0;

    // ===== stats =====
    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;

    // ===== runtime =====
    bool is_alive = true;
};

}  // namespace wg

#endif  // PEER_HPP
