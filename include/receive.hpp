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

constexpr char kMac1Label[] = "mac1----";
constexpr char kCookieLabel[] = "cookie--";

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
    uint64_t cookie_lifetime_seconds = COOKIE_LIFETIME;
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

    // 替换 receive 层配置。
    // 注意：load_monitor 是非拥有指针，调用方要保证其生命周期覆盖 Receiver 使用期。
    void set_config(ReceiveConfig config) { config_ = config; }

    // 手动强制或关闭 mac2 验证。
    // 测试、调试或 core 自己判断高负载时可以直接用这个开关。
    void set_force_mac2_validation(bool force) {
        config_.force_mac2_validation = force;
    }

    // 接入负载判断模块。monitor 为 nullptr 时只看 force_mac2_validation。
    void set_load_monitor(LoadMonitor* monitor) {
        config_.load_monitor = monitor;
    }

    // 当前是否要求握手包携带有效 mac2。
    // 结果来自手动强制开关或 LoadMonitor。
    bool needs_mac2_validation() const {
        return config_.force_mac2_validation ||
               (config_.load_monitor != nullptr &&
                config_.load_monitor->needs_mac2_validation());
    }

    // UDP 回调中最常用的入口。
    // 它负责识别消息类型、parse、mac 验证、必要时发 CookieReply，并调用 protocol。
    // plaintext_out 用于承接 transport 明文；结果中的 plaintext_size 表示有效长度。
    ReceiveResult handle_packet(UdpSocket& socket, NoiseProtocol& protocol,
                                PeerManager& peers, IndexTable& index_table,
                                std::span<const uint8_t> packet,
                                const Endpoint& src,
                                std::span<uint8_t> plaintext_out);

    // 消费 initiation。
    // 成功时返回 ConsumedInitiation 并带出 peer；高负载且 mac2 无效时会发送 CookieReply。
    ReceiveResult consume_initiation(UdpSocket& socket, NoiseProtocol& protocol,
                                     PeerManager& peers,
                                     const HandshakeInitiation& msg,
                                     const Endpoint& src);

    // 消费 response。
    // 成功时返回 ConsumedResponse 并带出 peer；通常随后由 core 轮转 keypair。
    ReceiveResult consume_response(NoiseProtocol& protocol, PeerManager& peers,
                                   IndexTable& index_table,
                                   const HandshakeResponse& msg,
                                   const Endpoint& src);

    // 消费 transport data。
    // ciphertext_size 是 packet 中真实密文长度；plaintext_out 必须至少容纳
    // ciphertext_size - TAG_SIZE 字节。
    ReceiveResult consume_transport(NoiseProtocol& protocol,
                                    IndexTable& index_table,
                                    const TransportData& msg,
                                    size_t ciphertext_size, const Endpoint& src,
                                    std::span<uint8_t> plaintext_out);

    // 识别 CookieReply。
    // 真正解密并更新发送侧 cookie 的动作交给 Sender::consume_cookie_reply。
    ReceiveResult consume_cookie_reply(const CookieReply& msg,
                                       const Endpoint& src);

    // 校验 mac1。
    // mac1 证明发送方知道接收方静态公钥，可用于丢弃明显无效的握手包。
    bool verify_mac1(const HandshakeInitiation& msg) const;
    bool verify_mac1(const HandshakeResponse& msg) const;

    // 校验 mac2。
    // mac2 绑定源 endpoint，用于高负载时确认对方能收到 CookieReply。
    bool verify_mac2(const HandshakeInitiation& msg, const Endpoint& src) const;
    bool verify_mac2(const HandshakeResponse& msg, const Endpoint& src) const;

    // 构造 CookieReply。
    // mac1 用作 AEAD associated data；receiver_index 通常取对方握手包里的 sender_index。
    bool create_cookie_reply(const Mac& mac1, const Endpoint& src,
                             KeypairIndex receiver_index,
                             CookieReply& out) const;

    // 只读取首字节判断消息类型，不做长度校验。
    static std::optional<MessageType> peek_message_type(
        std::span<const uint8_t> packet);

    // 解析固定长度消息。packet 长度必须精确等于对应结构体大小。
    static bool parse_initiation(std::span<const uint8_t> packet,
                                 HandshakeInitiation& out);
    static bool parse_response(std::span<const uint8_t> packet,
                               HandshakeResponse& out);
    static bool parse_cookie_reply(std::span<const uint8_t> packet,
                                   CookieReply& out);

    // TransportData 是变长 wire 格式：固定 header + ciphertext。
    // ciphertext_size = packet.size() - sizeof(TransportDataHeader)。
    // out.encrypted_data 只填入 ciphertext_size 部分，其余清零。
    static bool parse_transport(std::span<const uint8_t> packet,
                                TransportData& out, size_t& ciphertext_size);

   private:
    PublicKey local_static_{};
    ReceiveConfig config_{};
};

}  // namespace wg

#endif  // RECEIVE_HPP
