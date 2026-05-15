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
          endpoint_(config.endpoint) {}

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
    void set_precomputed_static_static(const SharedSecret&);

    Handshake& handshake() { return handshake_; }  // 返回的是引用，方便外部修改
    KeypairManager& keypairs() { return keypairs_; }

   private:
    // peer 的长期身份信息 自己存一个
    PublicKey remote_static_{};
    PreSharedKey preshared_key_{};
    std::optional<Endpoint> endpoint_;

    // 与 peer 绑定的长期预计算缓存也就是secret
    SharedSecret precomputed_static_static_{};
    // HASH(H_{init} || S^{pub}_r)，也就是base_hash
    Hash base_hash_{};

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