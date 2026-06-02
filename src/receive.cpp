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

// 入口函数，负责识别消息类型并分发到对应的处理函数。
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
            if (config_.load_monitor != nullptr) {
                config_.load_monitor->observe_handshake();
            }
            HandshakeInitiation msg{};
            if (!parse_initiation(packet, msg)) {
                return result(ReceiveAction::Drop, ReceiveError::ShortPacket,
                              src);
            }
            return consume_initiation(socket, protocol, peers, msg, src);
        }
        case MessageType::HandshakeResponse: {
            if (config_.load_monitor != nullptr) {
                config_.load_monitor->observe_handshake();
            }
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
            return consume_cookie_reply(msg, src);
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
                                           const HandshakeInitiation& msg,
                                           const Endpoint& src) {
    if (!verify_mac1(msg)) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidMac1, src);
    }

    if (needs_mac2_validation() && !verify_mac2(msg, src)) {
        CookieReply reply{};
        if (!create_cookie_reply(msg.mac1, src, msg.sender_index, reply)) {
            return result(ReceiveAction::Drop, ReceiveError::CryptoFailed, src);
        }

        const auto bytes = wire_bytes(reply);
        const ssize_t sent = socket.send_bytes(bytes, src);
        if (sent != static_cast<ssize_t>(bytes.size())) {
            return result(ReceiveAction::Drop, ReceiveError::SocketFailed, src);
        }
        return result(ReceiveAction::SentCookieReply, ReceiveError::InvalidMac2,
                      src);
    }

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
                                         const HandshakeResponse& msg,
                                         const Endpoint& src) {
    if (!verify_mac1(msg)) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidMac1, src);
    }
    if (needs_mac2_validation() && !verify_mac2(msg, src)) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidMac2, src);
    }

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

ReceiveResult Receiver::consume_transport(NoiseProtocol& protocol,
                                          IndexTable& index_table,
                                          const TransportData& msg,
                                          size_t ciphertext_size,
                                          const Endpoint& src,
                                          std::span<uint8_t> plaintext_out) {
    if (ciphertext_size < TAG_SIZE) {
        return result(ReceiveAction::Drop, ReceiveError::ShortPacket, src);
    }

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

ReceiveResult Receiver::consume_cookie_reply(const CookieReply& msg,
                                             const Endpoint& src) {
    return result(ReceiveAction::ConsumedCookieReply, ReceiveError::None, src);
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
