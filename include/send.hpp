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

constexpr char kMac1Label[] = "mac1----";
constexpr char kCookieLabel[] = "cookie--";

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
    explicit Sender(const PublicKey& local_static)
        : local_static_(local_static) {}

    // 握手的两条消息都可以出发cookie challenge
    // 我们设置默认行为，在受到cookie reply的时候
    // 从keypair取出mac1,解密出cookie.然后清空除了mac1和cookie以外的其他字段
    // 然后重新发第一条消息重新握手
    bool consume_cookie_reply(const CookieReply& msg, IndexTable& index_table);

    // 为握手包计算 mac1。
    // receiver_static 是接收方长期静态公钥；mac1 覆盖消息中 mac1 之前的字节。
    // 该函数也会保存本次 mac1，供后续 CookieReply 解密使用。
    bool fill_mac1(HandshakeInitiation& msg, const PublicKey& receiver_static);
    bool fill_mac1(HandshakeResponse& msg, const PublicKey& receiver_static);

    // 为握手包计算 mac2。
    // 只有当前保存的 cookie 仍有效时才填入真实 mac2；否则 mac2 置 0 并返回
    // true。 dst 预留给按 endpoint 绑定 cookie 的实现；当前接口保持这个上下文。
    bool fill_mac2(HandshakeInitiation& msg, const Endpoint& dst) const;
    bool fill_mac2(HandshakeResponse& msg, const Endpoint& dst) const;

    // 只构造 initiation，不发送。
    // 内部调用 NoiseProtocol::create_initiation，并补齐 mac1/mac2。
    bool create_initiation(NoiseProtocol& protocol, Peer& peer,
                           Keypair& keypair, HandshakeInitiation& msg);

    // 只构造 response，不发送。
    // 通常在 receive 层成功消费 initiation 后，由 core 分配 keypair 再调用。
    bool create_response(NoiseProtocol& protocol, Peer& peer, Keypair& keypair,
                         HandshakeResponse& msg);

    // 只构造 transport data，不发送。
    // plaintext 长度不能超过 PAYLOAD_MAX_SIZE；counter/nonce 由 protocol
    // 层处理。
    bool create_transport(NoiseProtocol& protocol, Keypair& keypair,
                          std::span<const uint8_t> plaintext,
                          TransportData& msg);

    // 构造并发送 initiation。Peer 必须已经有 endpoint。
    // 返回 ok=false 表示构造失败、缺少 endpoint 或 socket 发送失败。
    SendResult send_initiation(UdpSocket& socket, NoiseProtocol& protocol,
                               Peer& peer, Keypair& keypair);

    // 构造并发送 response。Peer 必须已经有 endpoint。
    SendResult send_response(UdpSocket& socket, NoiseProtocol& protocol,
                             Peer& peer, Keypair& keypair);

    // 构造并发送 transport data。Peer 必须已经有 endpoint。
    // bytes_sent 是最终 UDP payload 的字节数，不是 plaintext 长度。
    SendResult send_transport(UdpSocket& socket, NoiseProtocol& protocol,
                              Peer& peer, Keypair& keypair,
                              std::span<const uint8_t> plaintext);

    // CookieReply 是 receive 层在负载较高或 mac2 不满足时发回去的控制包。
    // 这里仅负责把已经构造好的 CookieReply 发到指定 endpoint。
    SendResult send_cookie_reply(UdpSocket& socket, const Endpoint& dst,
                                 const CookieReply& msg) const;

    // 返回固定长度消息的 wire 视图。
    // 视图直接指向 msg 本身，msg 生命周期结束后 span 失效。
    static std::span<const uint8_t> wire_bytes(const HandshakeInitiation& msg);
    static std::span<const uint8_t> wire_bytes(const HandshakeResponse& msg);
    static std::span<const uint8_t> wire_bytes(const CookieReply& msg);

    // TransportData 的 wire 长度取决于明文长度：
    // sizeof(TransportDataHeader) + plaintext_size + TAG_SIZE。
    // out 会被 resize 并写入完整 UDP payload。
    static bool serialize_transport(const TransportData& msg,
                                    size_t plaintext_size,
                                    std::vector<uint8_t>& out);

   private:
    PublicKey local_static_{};
};

}  // namespace wg

#endif  // SEND_HPP
