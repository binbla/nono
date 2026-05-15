#ifndef RECEIVE_HPP
#define RECEIVE_HPP
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "endpoint.hpp"
#include "index_table.hpp"
#include "load_monitor.hpp"
#include "messages.hpp"
#include "peer.hpp"
#include "peer_manager.hpp"
#include "protocol.hpp"
#include "socket_c.hpp"
#include "types.hpp"

namespace wg {

enum class ReceiveAction {
    Drop,
    ConsumedCookieReply,
    ConsumedInitiation,
    ConsumedResponse,
    ConsumedTransport,
    SentCookieReply,
};

enum class ReceiveError {
    None,
    ShortPacket,
    UnknownMessageType,
    InvalidReserved,
    InvalidMac1,
    InvalidMac2,
    UnknownPeer,
    UnknownIndex,
    CryptoFailed,
    Replay,
    OutputTooSmall,
    SocketFailed,
};

struct ReceiveConfig {
    // 手动强制 mac2 验证，适合测试或 core 直接接管负载策略。
    bool force_mac2_validation = false;

    // 可选的非拥有指针。存在时 receive 层直接询问它是否需要 mac2。
    LoadMonitor* load_monitor = nullptr;

    // mac2/cookie 的有效期由实现层使用，头文件只固定配置入口。
    uint64_t cookie_lifetime_seconds = 120;
};

struct ReceiveResult {
    ReceiveAction action = ReceiveAction::Drop;
    ReceiveError error = ReceiveError::None;

    Peer* peer = nullptr;
    Keypair* keypair = nullptr;
    Endpoint source{};

    // transport 成功解密后，上层读取 plaintext[0..plaintext_size)。
    size_t plaintext_size = 0;
};

class Receiver {
    // Receiver 是协议外层的“入站分发”：
    // - 从 UDP datagram 判断消息类型
    // - 验证 handshake 的 mac1 / mac2
    // - 必要时生成并发送 CookieReply
    // - 调 NoiseProtocol 消费握手和数据消息
    //
    // 它不拥有 Peer/Keypair/Socket。core 负责把这些对象传进来。
   public:
    explicit Receiver(const PublicKey& local_static,
                      ReceiveConfig config = ReceiveConfig{})
        : local_static_(local_static), config_(config) {}

    const ReceiveConfig& config() const { return config_; }
    void set_config(ReceiveConfig config) { config_ = config; }
    void set_force_mac2_validation(bool force) {
        config_.force_mac2_validation = force;
    }
    void set_load_monitor(LoadMonitor* monitor) {
        config_.load_monitor = monitor;
    }

    bool needs_mac2_validation() const {
        return config_.force_mac2_validation ||
               (config_.load_monitor != nullptr &&
                config_.load_monitor->needs_mac2_validation());
    }

    // UDP 回调中最常用的入口。plaintext_out 用于承接 transport 明文。
    ReceiveResult handle_packet(UdpSocket& socket, NoiseProtocol& protocol,
                                PeerManager& peers, IndexTable& index_table,
                                std::span<const uint8_t> packet,
                                const Endpoint& src,
                                std::span<uint8_t> plaintext_out);

    ReceiveResult consume_initiation(UdpSocket& socket,
                                     NoiseProtocol& protocol,
                                     PeerManager& peers,
                                     const HandshakeInitiation& msg,
                                     const Endpoint& src);

    ReceiveResult consume_response(NoiseProtocol& protocol, PeerManager& peers,
                                   IndexTable& index_table,
                                   const HandshakeResponse& msg,
                                   const Endpoint& src);

    ReceiveResult consume_transport(NoiseProtocol& protocol,
                                    IndexTable& index_table,
                                    const TransportData& msg,
                                    size_t ciphertext_size,
                                    const Endpoint& src,
                                    std::span<uint8_t> plaintext_out);

    ReceiveResult consume_cookie_reply(const CookieReply& msg,
                                       const Endpoint& src);

    bool verify_mac1(const HandshakeInitiation& msg) const;
    bool verify_mac1(const HandshakeResponse& msg) const;

    bool verify_mac2(const HandshakeInitiation& msg,
                     const Endpoint& src) const;
    bool verify_mac2(const HandshakeResponse& msg, const Endpoint& src) const;

    bool create_cookie_reply(const Mac& mac1, const Endpoint& src,
                             KeypairIndex receiver_index,
                             CookieReply& out) const;

    static std::optional<MessageType> peek_message_type(
        std::span<const uint8_t> packet);

    static bool parse_initiation(std::span<const uint8_t> packet,
                                 HandshakeInitiation& out);
    static bool parse_response(std::span<const uint8_t> packet,
                               HandshakeResponse& out);
    static bool parse_cookie_reply(std::span<const uint8_t> packet,
                                   CookieReply& out);

    // TransportData 是变长 wire 格式：固定 header + ciphertext。
    // ciphertext_size = packet.size() - sizeof(TransportDataHeader)。
    static bool parse_transport(std::span<const uint8_t> packet,
                                TransportData& out,
                                size_t& ciphertext_size);

   private:
    PublicKey local_static_{};
    ReceiveConfig config_{};
};

}  // namespace wg

#endif  // RECEIVE_HPP
