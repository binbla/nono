#include "send.hpp"

#include <cstring>

#include "crypto.hpp"
#include "utils.hpp"
namespace {
// 切割
std::span<const uint8_t> as_bytes(const void* ptr, size_t size) {
    return {reinterpret_cast<const uint8_t*>(ptr), size};
}

template <typename Message>
std::span<const uint8_t> bytes_until_mac1(const Message& msg) {
    return as_bytes(&msg, offsetof(Message, mac1));
}

template <typename Message>
std::span<const uint8_t> bytes_until_mac2(const Message& msg) {
    return as_bytes(&msg, offsetof(Message, mac2));
}

template <typename Message>
std::span<const uint8_t> wire_bytes(const Message& msg) {
    return as_bytes(&msg, sizeof(msg));
}
}  // namespace
namespace wg {

// mac 这个函数的实现和公式的参数顺序不一样。
// 这里的mac函数是data,key,out的参数顺序
template <typename Message>
bool Sender::fill_mac1(Message& msg, const Hash& precomputed_mac1_hash) {
    return crypto::mac(bytes_until_mac1(msg), precomputed_mac1_hash, msg.mac1);
}
template <typename Message>
bool Sender::fill_mac2(Message& msg, const Cookie& cookie) const {
    return crypto::mac(bytes_until_mac2(msg), cookie, msg.mac2);
}

// 握手的这两个数据包都是数据流，不需要管大小端
SendResult Sender::send_initiation(UdpSocket& socket, NoiseProtocol& protocol,
                                   Peer& peer, Keypair& keypair) {
    // peer有合法的endpoint才发送握手消息
    if (!peer.endpoint()) {
        return {};
    }
    HandshakeInitiation msg{};
    // 填充协议层面消息内容
    protocol.create_initiation(peer, keypair, msg);
    // 序列化
    msg.sender_index = wg::wire::host_to_le32(keypair.local_index);
    // 填充 mac1 和 mac2
    fill_mac1(msg, peer.precomputed_mac1_hash());
    if (!crypto::is_all_zero(keypair.last_cookie)) {
        fill_mac2(msg, keypair.last_cookie);
    }

    keypair.last_mac1 = msg.mac1;

    const std::span<const uint8_t> bytes = wire_bytes(msg);

    const ssize_t sent = socket.send_bytes(bytes, *peer.endpoint());
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

SendResult Sender::send_response(UdpSocket& socket, NoiseProtocol& protocol,
                                 Peer& peer, Keypair& keypair) {
    if (!peer.endpoint()) {
        return {};
    }
    HandshakeResponse msg{};
    // 填充消息
    protocol.create_response(peer, keypair, msg);
    // 序列化
    msg.sender_index = wg::wire::host_to_le32(keypair.local_index);
    msg.receiver_index = wg::wire::host_to_le32(keypair.remote_index);
    // 填充 mac1 和 mac2
    fill_mac1(msg, peer.precomputed_mac1_hash());
    if (!crypto::is_all_zero(keypair.last_cookie)) {
        fill_mac2(msg, keypair.last_cookie);
    }
    keypair.last_mac1 = msg.mac1;

    const std::span<const uint8_t> bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, *peer.endpoint());
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

SendResult Sender::send_cookie_reply(UdpSocket& socket, NoiseProtocol& protocol,
                                     KeypairIndex receiver_index,
                                     const Mac& mac1, const Endpoint& dst) {
    CookieReply msg{};

    // 初始化
    msg.message_type = MessageType::CookieReply;
    msg.receiver_index = receiver_index;

    // 生成随机nonce
    crypto::fill_random(msg.nonce);
    // 抓出ip:port
    std::span<const uint8_t> data = as_bytes(dst.addr(), dst.size());
    // 算出cookie
    Cookie cookie{};
    crypto::mac(data, protocol.secret_for_cookie(), cookie);
    // 加密cookie
    // key : protocol.precomputed_mac2_hash()
    // nonce : out.nonce
    // ad : mac1
    // plaintext : cookie
    // ciphertext : out.encrypted_cookie
    crypto::xaead_encrypt(protocol.precomputed_mac2_hash(), msg.nonce, mac1,
                          cookie, msg.encrypted_cookie);
    // 发送之前序列化。注意顺序
    msg.receiver_index = wg::wire::host_to_le32(receiver_index);

    const std::span<const uint8_t> bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, dst);
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

SendResult Sender::send_transport(UdpSocket& socket, NoiseProtocol& protocol,
                                  Peer& peer,
                                  std::span<const uint8_t> plaintext) {
    Keypair* keypair = peer.keypairs().current().get();
    if (!keypair || !keypair->is_sendable()) {
        return {};
    }

    TransportData msg{};
    protocol.create_datatrans(*keypair, plaintext, msg);
    // 序列化 原地操作
    msg.header.receiver_index =
        wg::wire::host_to_le32(msg.header.receiver_index);
    msg.header.counter = wg::wire::host_to_le64(msg.header.counter);

    const std::span<const uint8_t> bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, *peer.endpoint());
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

SendResult Sender::send_keepalive(UdpSocket& socket, NoiseProtocol& protocol,
                                  Peer& peer) {
    if (!peer.endpoint()) {
        return {};
    }

    Keypair* keypair = peer.keypairs().current().get();
    if (!keypair || !keypair->is_sendable()) {
        return {};
    }

    TransportData msg{};
    protocol.create_datatrans(*keypair, std::span<const uint8_t>(), msg);
    // 序列化 原地操作
    msg.header.receiver_index =
        wg::wire::host_to_le32(msg.header.receiver_index);
    msg.header.counter = wg::wire::host_to_le64(msg.header.counter);

    const std::span<const uint8_t> bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, *peer.endpoint());
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

}  // namespace wg
