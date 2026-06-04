#ifndef SEND_HPP
#define SEND_HPP
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
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

struct SendResult {
    bool ok = false;
    size_t bytes_sent = 0;
};

// 上层要负责可用性验证
class Sender {
    // Sender 是协议外层的“出站封装”：
    // - 调 NoiseProtocol 创建握手/数据消息
    // - 填充 mac1 / mac2
    // - 消费 CookieReply，更新发送侧 cookie
    // - 把最终 wire bytes 交给 UdpSocket 发出
    //
    // 它不管理 Peer/Keypair 生命周期，也不决定何时握手或重传。
   public:
    using PacketLogger = std::function<void(std::span<const uint8_t>)>;

    explicit Sender(const PublicKey& local_static)
        : local_static_(local_static) {}

    void set_packet_logger(PacketLogger logger) {
        packet_logger_ = std::move(logger);
    }

    // 为握手包计算 mac1 和 mac2。
    // mac1 的材料是msg和peer里面的预计算mac1_hash
    // mac2 的材料是msg和cookie，cookie 自接收后保存在keypair里面
    template <typename Message>
    bool fill_mac1(Message& msg, const Hash& mac1_hash);
    template <typename Message>
    bool fill_mac2(Message& msg, const Cookie& cookie) const;

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
                              Peer& peer, std::span<const uint8_t> plaintext);

    // CookieReply 是 receive 层在负载较高或 mac2 不满足时发回去的控制包。
    // 这里仅负责把已经构造好的 CookieReply 发到指定 endpoint。
    SendResult send_cookie_reply(UdpSocket& socket, NoiseProtocol& protocol,
                                 KeypairIndex receiver_index, const Mac& mac1,
                                 const Endpoint& dst);

    SendResult send_keepalive(UdpSocket& socket, NoiseProtocol& protocol,
                              Peer& peer);

    // 具体消息的序列化，特别是 TransportData 需要把 header 和加密数据拼成连续的
    // bytes。
    static bool serialize_transport(const TransportData& msg,
                                    size_t plaintext_size,
                                    std::vector<uint8_t>& out);

   private:
    PublicKey local_static_{};
    PacketLogger packet_logger_;
};

}  // namespace wg

#endif  // SEND_HPP
