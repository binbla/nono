#include "receive.hpp"

#include <cstring>

#include "crypto.hpp"

namespace wg {
namespace {

std::span<const uint8_t> as_bytes(const void* ptr, size_t size) {
    return {reinterpret_cast<const uint8_t*>(ptr), size};
}

bool derive_labeled_key(std::span<const uint8_t> label,
                        std::span<const uint8_t> data, SymmetricKey& out) {
    std::array<uint8_t, 64> input{};
    if (label.size() + data.size() > input.size()) {
        return false;
    }

    std::memcpy(input.data(), label.data(), label.size());
    std::memcpy(input.data() + label.size(), data.data(), data.size());
    return crypto::hash(
        std::span<const uint8_t>(input.data(), label.size() + data.size()),
        out);
}

bool derive_mac1_key(const PublicKey& receiver_static, SymmetricKey& out) {
    return derive_labeled_key(as_bytes(kMac1Label, sizeof(kMac1Label) - 1),
                              receiver_static, out);
}

bool derive_cookie_key(const Mac& mac1, SymmetricKey& out) {
    return derive_labeled_key(as_bytes(kCookieLabel, sizeof(kCookieLabel) - 1),
                              mac1, out);
}

template <typename Message>
std::span<const uint8_t> bytes_until_mac1(const Message& msg) {
    return as_bytes(&msg, offsetof(Message, mac1));
}

template <typename Message>
std::span<const uint8_t> bytes_until_mac2(const Message& msg) {
    return as_bytes(&msg, offsetof(Message, mac2));
}

bool compute_mac1(std::span<const uint8_t> data,
                  const PublicKey& receiver_static, Mac& out) {
    SymmetricKey key{};
    if (!derive_mac1_key(receiver_static, key)) {
        return false;
    }
    const bool ok = crypto::mac(data, key, out);
    crypto::secure_zero(key);
    return ok;
}

bool endpoint_cookie(const PublicKey& local_static, const Endpoint& src,
                     std::array<uint8_t, COOKIE_SIZE>& out) {
    Mac cookie{};
    if (!crypto::mac(as_bytes(src.addr(), src.size()), local_static, cookie)) {
        return false;
    }
    out = cookie;
    return true;
}

bool compute_mac2(std::span<const uint8_t> data,
                  const std::array<uint8_t, COOKIE_SIZE>& cookie, Mac& out) {
    return crypto::mac(data, cookie, out);
}

ReceiveResult result(ReceiveAction action, ReceiveError error,
                     const Endpoint& src) {
    ReceiveResult r;
    r.action = action;
    r.error = error;
    r.source = src;
    return r;
}

template <typename Message>
bool parse_fixed(std::span<const uint8_t> packet, Message& out) {
    if (packet.size() != sizeof(Message)) {
        return false;
    }
    std::memcpy(&out, packet.data(), sizeof(Message));
    return true;
}

bool reserved_is_zero(const uint8_t (&reserved)[3]) {
    return reserved[0] == 0 && reserved[1] == 0 && reserved[2] == 0;
}

std::span<const uint8_t> wire_bytes(const CookieReply& msg) {
    return as_bytes(&msg, sizeof(msg));
}

}  // namespace

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
    if (!reserved_is_zero(msg.reserved)) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidReserved, src);
    }
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
    if (!reserved_is_zero(msg.reserved)) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidReserved, src);
    }
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
    if (!reserved_is_zero(msg.header.reserved)) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidReserved, src);
    }
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
    if (!reserved_is_zero(msg.reserved)) {
        return result(ReceiveAction::Drop, ReceiveError::InvalidReserved, src);
    }

    return result(ReceiveAction::ConsumedCookieReply, ReceiveError::None, src);
}

bool Receiver::verify_mac1(const HandshakeInitiation& msg) const {
    Mac expected{};
    return compute_mac1(bytes_until_mac1(msg), local_static_, expected) &&
           crypto::constant_time_equal(expected, msg.mac1);
}

bool Receiver::verify_mac1(const HandshakeResponse& msg) const {
    Mac expected{};
    return compute_mac1(bytes_until_mac1(msg), local_static_, expected) &&
           crypto::constant_time_equal(expected, msg.mac1);
}

bool Receiver::verify_mac2(const HandshakeInitiation& msg,
                           const Endpoint& src) const {
    std::array<uint8_t, COOKIE_SIZE> cookie{};
    Mac expected{};
    return endpoint_cookie(local_static_, src, cookie) &&
           compute_mac2(bytes_until_mac2(msg), cookie, expected) &&
           crypto::constant_time_equal(expected, msg.mac2);
}

bool Receiver::verify_mac2(const HandshakeResponse& msg,
                           const Endpoint& src) const {
    std::array<uint8_t, COOKIE_SIZE> cookie{};
    Mac expected{};
    return endpoint_cookie(local_static_, src, cookie) &&
           compute_mac2(bytes_until_mac2(msg), cookie, expected) &&
           crypto::constant_time_equal(expected, msg.mac2);
}

bool Receiver::create_cookie_reply(const Mac& mac1, const Endpoint& src,
                                   KeypairIndex receiver_index,
                                   CookieReply& out) const {
    out.message_type = MessageType::CookieReply;
    out.reserved[0] = 0;
    out.reserved[1] = 0;
    out.reserved[2] = 0;
    out.receiver_index = receiver_index;
    out.nonce.fill(0);
    out.encrypted_cookie.fill(0);

    std::array<uint8_t, COOKIE_SIZE> cookie{};
    SymmetricKey key{};
    if (!endpoint_cookie(local_static_, src, cookie) ||
        !derive_cookie_key(mac1, key) || !crypto::fill_random(out.nonce)) {
        crypto::secure_zero(key);
        return false;
    }

    const bool ok = crypto::xaead_encrypt(key, out.nonce, mac1, cookie,
                                          out.encrypted_cookie);
    crypto::secure_zero(key);
    return ok;
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

bool Receiver::parse_initiation(std::span<const uint8_t> packet,
                                HandshakeInitiation& out) {
    return parse_fixed(packet, out);
}

bool Receiver::parse_response(std::span<const uint8_t> packet,
                              HandshakeResponse& out) {
    return parse_fixed(packet, out);
}

bool Receiver::parse_cookie_reply(std::span<const uint8_t> packet,
                                  CookieReply& out) {
    return parse_fixed(packet, out);
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

}  // namespace wg
