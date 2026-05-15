#ifndef NOISE_PROTOCOL_HPP
#define NOISE_PROTOCOL_HPP

#include <array>
#include <cstdint>
#include <span>

#include "crypto.hpp"
#include "index_table.hpp"
#include "messages.hpp"
#include "noise.hpp"
#include "peer.hpp"
#include "peer_manager.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace wg {

class NoiseProtocol {
    // NoiseProtocol 负责 Noise 协议相关的所有状态和操作，包括：
    // - 本地长期密钥对（身份）
    // - 预计算的 base_chaining_key 和 base_hash
    // - 握手消息的创建和消费逻辑
   public:
    NoiseProtocol() = default;
    ~NoiseProtocol();

    NoiseProtocol(const NoiseProtocol&) = delete;
    NoiseProtocol& operator=(const NoiseProtocol&) = delete;

    NoiseProtocol(NoiseProtocol&&) = delete;
    NoiseProtocol& operator=(NoiseProtocol&&) = delete;

    // Initialization
    bool initialize(const PrivateKey& local_private,
                    const PublicKey& local_public);

    bool generate_identity(PrivateKey& out_private, PublicKey& out_public);

    void clear();

    bool initialized() const { return initialized_; }

    const PrivateKey& local_private() const { return local_private_; }
    const PublicKey& local_public() const { return local_public_; }

    // 返回预计算的 base_chaining_key 和 base_hash，供外部 handshake 初始化使用
    const ChainingKey& base_chaining_key() const { return base_chaining_key_; }
    const Hash& base_hash() const { return base_hash_; }

    // ================================================================
    // NoiseProtocol::handshake initiater
    // ================================================================
    bool create_initiation(Peer& peer, Keypair& keypair,
                           HandshakeInitiation& msg);

    Peer* consume_initiation(const HandshakeInitiation& msg,
                             PeerManager& peers);

    // ================================================================
    // NoiseProtocol::handshake responder
    // ================================================================
    bool create_response(Peer& peer, Keypair& keypair, HandshakeResponse& msg);

    Peer* consume_response(const HandshakeResponse& msg, PeerManager& peers,
                           IndexTable& index_table);

    // ================================================================
    // NoiseProtocol::data transport
    // ================================================================

    bool create_datatrans(Keypair& keypair, std::span<const uint8_t> data,
                          TransportData& msg);

    bool consume_datatrans(IndexTable& index_table, const TransportData& msg,
                           std::span<uint8_t> data);

   private:
    bool initialized_ = false;

    PrivateKey local_private_{};
    PublicKey local_public_{};

    ChainingKey base_chaining_key_{};
    Hash base_hash_{};

   private:
    // 内部辅助函数

    bool initialize_initiator_handshake(Peer& peer, Handshake& hs) const;

    bool initialize_responder_handshake(ChainingKey& ck, Hash& h) const;

    bool ready() const { return initialized_; }
};

}  // namespace wg

#endif  // NOISE_PROTOCOL_HPP