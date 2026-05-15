#ifndef SEND_HPP
#define SEND_HPP
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "endpoint.hpp"
#include "messages.hpp"
#include "peer.hpp"
#include "protocol.hpp"
#include "socket_c.hpp"
#include "tai64n.hpp"
#include "types.hpp"

namespace wg {

// 发送侧维护的 cookie 状态。
// mac1 每个握手包都要填；mac2 只有收到对方 CookieReply 后才有能力填。
struct SendCookieState {
    std::array<uint8_t, COOKIE_SIZE> cookie{};
    Timestamp received_at{};
    bool valid = false;

    void clear() {
        cookie.fill(0);
        received_at.clear();
        valid = false;
    }
};

struct SendConfig {
    // 对端返回的 cookie 可以用多久。超时后继续只填 mac1，mac2 置 0。
    uint64_t cookie_lifetime_seconds = 120;
};

struct SendResult {
    bool ok = false;
    size_t bytes_sent = 0;
};

class Sender {
    // Sender 是协议外层的“出站封装”：
    // - 调 NoiseProtocol 创建握手/数据消息
    // - 填充 mac1 / mac2
    // - 消费 CookieReply，更新发送侧 cookie
    // - 把最终 wire bytes 交给 UdpSocket 发出
    //
    // 它不管理 Peer/Keypair 生命周期，也不决定何时握手或重传。
   public:
    explicit Sender(const PublicKey& local_static,
                    SendConfig config = SendConfig{})
        : local_static_(local_static), config_(config) {}

    const SendCookieState& cookie_state() const { return cookie_; }
    void clear_cookie() { cookie_.clear(); }

    // CookieReply 由 receive 层识别后交给 send 层消费。
    // 成功后后续 handshake 包会携带 mac2。
    bool consume_cookie_reply(const CookieReply& msg);

    bool fill_mac1(HandshakeInitiation& msg,
                   const PublicKey& receiver_static) const;
    bool fill_mac1(HandshakeResponse& msg,
                   const PublicKey& receiver_static) const;

    bool fill_mac2(HandshakeInitiation& msg, const Endpoint& dst) const;
    bool fill_mac2(HandshakeResponse& msg, const Endpoint& dst) const;

    // 只构造消息，不发送。适合 core 做排队、测试或交给 socket 池选择出口。
    bool create_initiation(NoiseProtocol& protocol, Peer& peer,
                           Keypair& keypair, HandshakeInitiation& msg);
    bool create_response(NoiseProtocol& protocol, Peer& peer, Keypair& keypair,
                         HandshakeResponse& msg);
    bool create_transport(NoiseProtocol& protocol, Keypair& keypair,
                          std::span<const uint8_t> plaintext,
                          TransportData& msg);

    // 构造并发送。Peer 必须已经有 endpoint。
    SendResult send_initiation(UdpSocket& socket, NoiseProtocol& protocol,
                               Peer& peer, Keypair& keypair);
    SendResult send_response(UdpSocket& socket, NoiseProtocol& protocol,
                             Peer& peer, Keypair& keypair);
    SendResult send_transport(UdpSocket& socket, NoiseProtocol& protocol,
                              Peer& peer, Keypair& keypair,
                              std::span<const uint8_t> plaintext);

    // CookieReply 是 receive 层在负载较高或 mac2 不满足时发回去的控制包。
    SendResult send_cookie_reply(UdpSocket& socket, const Endpoint& dst,
                                 const CookieReply& msg) const;

    static std::span<const uint8_t> wire_bytes(
        const HandshakeInitiation& msg);
    static std::span<const uint8_t> wire_bytes(const HandshakeResponse& msg);
    static std::span<const uint8_t> wire_bytes(const CookieReply& msg);

    // TransportData 的 wire 长度取决于明文长度：
    // sizeof(TransportDataHeader) + plaintext_size + TAG_SIZE。
    static bool serialize_transport(const TransportData& msg,
                                    size_t plaintext_size,
                                    std::vector<uint8_t>& out);

   private:
    bool cookie_is_fresh(Timestamp now) const;

    PublicKey local_static_{};
    SendCookieState cookie_{};
    SendConfig config_{};
};

}  // namespace wg

#endif  // SEND_HPP
