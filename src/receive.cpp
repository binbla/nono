#include "receive.hpp"

#include <cstring>

#include "crypto.hpp"
#include "messages.hpp"
#include "types.hpp"

namespace {

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
ReceiveResult result(ReceiveAction action, ReceiveError error,
                     const Endpoint& src) {
    ReceiveResult r;
    r.action = action;
    r.error = error;
    r.source = src;
    return r;
}

template <typename Message>
bool Receiver::verify_mac1(const Message& msg,
                           const Hash& precomputed_mac1_hash) const {
    // 提取出mac1验证需要的部分：data 和 mac1
    std::span<const uint8_t> data = bytes_until_mac1(msg);
    std::span<const uint8_t> mac1 = as_bytes(&msg.mac1, sizeof(msg.mac1));
    // 计算 expected_mac1
    Mac expected_mac1{};
    crypto::mac(data, precomputed_mac1_hash, expected_mac1);
    // 比较
    return crypto::constant_time_equal(mac1, expected_mac1);
}

template <typename Message>
bool Receiver::verify_mac2(const Message& msg, const Endpoint& src,
                           const Bytes32& secret_for_cookie) const {
    // mac2 的验证需要用到 src endpoint 和 protocol 里预先计算的 hash
    std::span<const uint8_t> data = bytes_until_mac2(msg);
    std::span<const uint8_t> mac2 = as_bytes(&msg.mac2, sizeof(msg.mac2));
    // 跟send相同的cookie构造方式
    Cookie cookie{};
    std::span<const uint8_t> addr = as_bytes(src.addr(), src.size());
    crypto::mac(addr, secret_for_cookie, cookie);
    // 计算 expected_mac2
    Mac expected_mac2{};
    crypto::mac(data, cookie, expected_mac2);
    // 比较
    return crypto::constant_time_equal(mac2, expected_mac2);
}

// 入口函数，负责识别消息类型并分发到对应的处理函数。
// 1. 获取消息类型并验证基本长度
// 2. 根据消息类型调用对应的 consume_* 函数
ReceiveResult Receiver::handle_packet(
    UdpSocket& socket, NoiseProtocol& protocol, PeerManager& peers,
    IndexTable& index_table, std::span<const uint8_t> packet,
    const Endpoint& src, std::span<uint8_t> plaintext_out) {
    if (config_.load_monitor != nullptr) {
        config_.load_monitor->observe_packet();
    }

    const auto type = peek_message_type(packet);
    if (!type) {
        return result(ReceiveAction::Drop, ReceiveError::ShortPacket, src);
    }

    switch (*type) {
        case MessageType::HandshakeInitiation: {
            HandshakeInitiation msg{};
            if (!parse_initiation(packet, msg)) {
                return result(ReceiveAction::Drop, ReceiveError::ShortPacket,
                              src);
            }
            return consume_initiation(socket, protocol, peers, msg, src);
        }
        case MessageType::HandshakeResponse: {
            HandshakeResponse msg{};
            if (!parse_response(packet, msg)) {
                return result(ReceiveAction::Drop, ReceiveError::ShortPacket,
                              src);
            }
            return consume_response(protocol, peers, index_table, msg, src);
        }
        case MessageType::CookieReply: {
            CookieReply msg{};
            if (!parse_cookie_reply(packet, msg)) {
                return result(ReceiveAction::Drop, ReceiveError::ShortPacket,
                              src);
            }
            return consume_cookie_reply(msg, src, index_table);
        }
        case MessageType::TransportData: {
            TransportData msg{};
            size_t ciphertext_size = 0;
            if (!parse_transport(packet, msg, ciphertext_size)) {
                return result(ReceiveAction::Drop, ReceiveError::ShortPacket,
                              src);
            }
            return consume_transport(protocol, index_table, msg,
                                     ciphertext_size, src, plaintext_out);
        }
    }

    return result(ReceiveAction::Drop, ReceiveError::UnknownMessageType, src);
}

ReceiveResult Receiver::consume_initiation(UdpSocket& socket,
                                           NoiseProtocol& protocol,
                                           PeerManager& peers,
                                           HandshakeInitiation& msg,
                                           const Endpoint& src) {
    if (!verify_mac1(msg, protocol.precomputed_mac1_hash_self())) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidMac1, src);
    }

    if (needs_mac2_validation() &&
        !verify_mac2(msg, src, protocol.secret_for_cookie())) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidMac2, src);
    }
    // 反序列化
    msg.sender_index = wg::wire::le_to_host32(msg.sender_index);
    // 消费消息，找到对应的 peer。失败通常是因为未知的远程静态公钥。
    Peer* peer = protocol.consume_initiation(msg, peers);
    if (peer == nullptr) {
        return result(ReceiveAction::Drop, ReceiveError::UnknownPeer, src);
    }

    peer->set_endpoint(src);
    ReceiveResult out =
        result(ReceiveAction::ConsumedInitiation, ReceiveError::None, src);
    out.peer = peer;
    return out;
}

ReceiveResult Receiver::consume_response(NoiseProtocol& protocol,
                                         PeerManager& peers,
                                         IndexTable& index_table,
                                         HandshakeResponse& msg,
                                         const Endpoint& src) {
    if (!verify_mac1(msg, protocol.precomputed_mac1_hash_self())) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidMac1, src);
    }
    if (needs_mac2_validation() &&
        !verify_mac2(msg, src, protocol.secret_for_cookie())) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidMac2, src);
    }
    // 反序列化
    msg.sender_index = wg::wire::le_to_host32(msg.sender_index);
    msg.receiver_index = wg::wire::le_to_host32(msg.receiver_index);

    Peer* peer = protocol.consume_response(msg, peers, index_table);
    if (peer == nullptr) {
        return result(ReceiveAction::Drop, ReceiveError::UnknownIndex, src);
    }

    peer->set_endpoint(src);
    ReceiveResult out =
        result(ReceiveAction::ConsumedResponse, ReceiveError::None, src);
    out.peer = peer;
    return out;
}
ReceiveResult Receiver::consume_cookie_reply(CookieReply& msg,
                                             const Endpoint& src,
                                             IndexTable& index_table) {
    // 反序列化
    msg.receiver_index = wg::wire::le_to_host32(msg.receiver_index);
    // 找到对应的
    // keypair，通常是最近一次发起握手时用的那个。失败可能是因为过期的 cookie
    // reply。
    Keypair* keypair = index_table.find(msg.receiver_index);
    if (keypair == nullptr) {
        return result(ReceiveAction::Drop, ReceiveError::UnknownIndex, src);
    }
    Handshake& hs = keypair->owner->handshake();

    // 取出之前的mac1
    Mac expected_mac1 = hs.last_mac1;
    // 这个peer的预计算mac2 hash
    Hash precomputed_mac2_hash = keypair->owner->precomputed_mac2_hash();
    // 消息体里面的信息
    XNonce nonce = msg.nonce;

    Cookie cookie{};

    // decrypt
    crypto::xaead_decrypt(precomputed_mac2_hash, nonce, expected_mac1,
                          msg.encrypted_cookie, cookie);
    // 保存这个cookie到keypair里，供下一次发起握手时使用
    hs.last_cookie = cookie;

    return result(ReceiveAction::ConsumedCookieReply, ReceiveError::None, src);
}
ReceiveResult Receiver::consume_transport(NoiseProtocol& protocol,
                                          IndexTable& index_table,
                                          TransportData& msg,
                                          size_t ciphertext_size,
                                          const Endpoint& src,
                                          std::span<uint8_t> plaintext_out) {
    if (ciphertext_size < TAG_SIZE) {
        return result(ReceiveAction::Drop, ReceiveError::ShortPacket, src);
    }
    // 反序列化
    msg.header.receiver_index =
        wg::wire::le_to_host32(msg.header.receiver_index);
    msg.header.counter = wg::wire::le_to_host64(msg.header.counter);

    Keypair* keypair = index_table.find(msg.header.receiver_index);
    if (keypair == nullptr) {
        return result(ReceiveAction::Drop, ReceiveError::UnknownIndex, src);
    }

    const size_t plaintext_size = ciphertext_size - TAG_SIZE;
    if (plaintext_out.size() < plaintext_size) {
        return result(ReceiveAction::Drop, ReceiveError::OutputTooSmall, src);
    }

    std::span<uint8_t> plaintext(plaintext_out.data(), plaintext_size);
    if (!protocol.consume_datatrans(index_table, msg, plaintext)) {
        return result(ReceiveAction::Drop, ReceiveError::CryptoFailed, src);
    }

    ReceiveResult out =
        result(ReceiveAction::ConsumedTransport, ReceiveError::None, src);
    out.keypair = keypair;
    out.peer = keypair->owner;
    out.plaintext_size = plaintext_size;
    return out;
}

bool Receiver::parse_initiation(std::span<const uint8_t> packet,
                                HandshakeInitiation& out) {
    if (packet.size() < sizeof(HandshakeInitiation)) {
        return false;
    }
    std::memcpy(&out, packet.data(), sizeof(HandshakeInitiation));
    return out.message_type == MessageType::HandshakeInitiation;
}
bool Receiver::parse_response(std::span<const uint8_t> packet,
                              HandshakeResponse& out) {
    if (packet.size() < sizeof(HandshakeResponse)) {
        return false;
    }
    std::memcpy(&out, packet.data(), sizeof(HandshakeResponse));
    return out.message_type == MessageType::HandshakeResponse;
}
bool Receiver::parse_cookie_reply(std::span<const uint8_t> packet,
                                  CookieReply& out) {
    if (packet.size() < sizeof(CookieReply)) {
        return false;
    }
    std::memcpy(&out, packet.data(), sizeof(CookieReply));
    return out.message_type == MessageType::CookieReply;
}
bool Receiver::parse_transport(std::span<const uint8_t> packet,
                               TransportData& out, size_t& ciphertext_size) {
    if (packet.size() < sizeof(TransportDataHeader) + TAG_SIZE) {
        return false;
    }

    ciphertext_size = packet.size() - sizeof(TransportDataHeader);
    if (ciphertext_size > out.encrypted_data.size()) {
        return false;
    }

    std::memcpy(&out.header, packet.data(), sizeof(TransportDataHeader));
    out.encrypted_data.fill(0);
    std::memcpy(out.encrypted_data.data(),
                packet.data() + sizeof(TransportDataHeader), ciphertext_size);
    return out.header.message_type == MessageType::TransportData;
}
std::optional<MessageType> Receiver::peek_message_type(
    std::span<const uint8_t> packet) {
    if (packet.empty()) {
        return std::nullopt;
    }

    switch (packet[0]) {
        case static_cast<uint8_t>(MessageType::HandshakeInitiation):
            return MessageType::HandshakeInitiation;
        case static_cast<uint8_t>(MessageType::HandshakeResponse):
            return MessageType::HandshakeResponse;
        case static_cast<uint8_t>(MessageType::CookieReply):
            return MessageType::CookieReply;
        case static_cast<uint8_t>(MessageType::TransportData):
            return MessageType::TransportData;
        default:
            return std::nullopt;
    }
}

}  // namespace wg
