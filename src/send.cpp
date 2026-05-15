#include "send.hpp"

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

bool compute_mac2(std::span<const uint8_t> data,
                  const std::array<uint8_t, COOKIE_SIZE>& cookie, Mac& out) {
    return crypto::mac(data, cookie, out);
}

bool decrypt_cookie(const CookieReply& msg, const Mac& last_mac1,
                    std::array<uint8_t, COOKIE_SIZE>& cookie) {
    SymmetricKey key{};
    if (!derive_cookie_key(last_mac1, key)) {
        return false;
    }

    const bool ok =
        crypto::xaead_decrypt(key, msg.nonce, last_mac1, msg.encrypted_cookie,
                              std::span<uint8_t>(cookie.data(), cookie.size()));
    crypto::secure_zero(key);
    return ok;
}

}  // namespace

bool Sender::consume_cookie_reply(const CookieReply& msg,
                                  IndexTable& index_table) {
    KeypairIndex expected_index = msg.receiver_index;
    Keypair* keypair = index_table.find(expected_index);

    if (keypair == nullptr || crypto::is_all_zero(keypair->last_mac1)) {
        return false;
    }
    // 从msg里面取出明文nonce
    XNonce expected_nonce = msg.nonce;
    Cookie expected_cookie{};
    if (!decrypt_cookie(msg, keypair->last_mac1, keypair->last_cookie)) {
        return false;
    }
    keypair->clear_runtime();
    // 重新走握手流程
    send_initiation();  // TODO
}

bool Sender::fill_mac1(HandshakeInitiation& msg,
                       const PublicKey& receiver_static) {
    msg.mac1.fill(0);
    msg.mac2.fill(0);
    if (!compute_mac1(bytes_until_mac1(msg), receiver_static, msg.mac1)) {
        return false;
    }

    cookie_.last_mac1 = msg.mac1;
    cookie_.has_last_mac1 = true;
    return true;
}

bool Sender::fill_mac1(HandshakeResponse& msg,
                       const PublicKey& receiver_static) {
    msg.mac1.fill(0);
    msg.mac2.fill(0);
    if (!compute_mac1(bytes_until_mac1(msg), receiver_static, msg.mac1)) {
        return false;
    }

    cookie_.last_mac1 = msg.mac1;
    cookie_.has_last_mac1 = true;
    return true;
}

bool Sender::fill_mac2(HandshakeInitiation& msg, const Endpoint&) const {
    msg.mac2.fill(0);
    if (!cookie_is_fresh(Timestamp::now())) {
        return true;
    }
    return compute_mac2(bytes_until_mac2(msg), cookie_.cookie, msg.mac2);
}

bool Sender::fill_mac2(HandshakeResponse& msg, const Endpoint&) const {
    msg.mac2.fill(0);
    if (!cookie_is_fresh(Timestamp::now())) {
        return true;
    }
    return compute_mac2(bytes_until_mac2(msg), cookie_.cookie, msg.mac2);
}

bool Sender::create_initiation(NoiseProtocol& protocol, Peer& peer,
                               Keypair& keypair, HandshakeInitiation& msg) {
    if (!protocol.create_initiation(peer, keypair, msg)) {
        return false;
    }
    if (!fill_mac1(msg, peer.remote_static())) {
        return false;
    }
    keypair.last_mac1 = msg.mac1;
    const auto& endpoint = peer.endpoint();
    return !endpoint || fill_mac2(msg, *endpoint);
}

bool Sender::create_response(NoiseProtocol& protocol, Peer& peer,
                             Keypair& keypair, HandshakeResponse& msg) {
    if (!protocol.create_response(peer, keypair, msg)) {
        return false;
    }
    if (!fill_mac1(msg, peer.remote_static())) {
        return false;
    }
    const auto& endpoint = peer.endpoint();
    return !endpoint || fill_mac2(msg, *endpoint);
}

bool Sender::create_transport(NoiseProtocol& protocol, Keypair& keypair,
                              std::span<const uint8_t> plaintext,
                              TransportData& msg) {
    return protocol.create_datatrans(keypair, plaintext, msg);
}

SendResult Sender::send_initiation(UdpSocket& socket, NoiseProtocol& protocol,
                                   Peer& peer, Keypair& keypair) {
    if (!peer.endpoint()) {
        return {};
    }

    HandshakeInitiation msg{};
    if (!create_initiation(protocol, peer, keypair, msg)) {
        return {};
    }

    const auto bytes = wire_bytes(msg);
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
    if (!create_response(protocol, peer, keypair, msg)) {
        return {};
    }

    const auto bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, *peer.endpoint());
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

SendResult Sender::send_transport(UdpSocket& socket, NoiseProtocol& protocol,
                                  Peer& peer, Keypair& keypair,
                                  std::span<const uint8_t> plaintext) {
    if (!peer.endpoint()) {
        return {};
    }

    TransportData msg{};
    if (!create_transport(protocol, keypair, plaintext, msg)) {
        return {};
    }

    std::vector<uint8_t> bytes;

    if (!serialize_transport(msg, plaintext.size(), bytes)) {
        return {};
    }

    const ssize_t sent =
        socket.send_bytes({bytes.data(), bytes.size()}, *peer.endpoint());
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

SendResult Sender::send_cookie_reply(UdpSocket& socket, const Endpoint& dst,
                                     const CookieReply& msg) const {
    const auto bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, dst);
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}

std::span<const uint8_t> Sender::wire_bytes(const HandshakeInitiation& msg) {
    return as_bytes(&msg, sizeof(msg));
}

std::span<const uint8_t> Sender::wire_bytes(const HandshakeResponse& msg) {
    return as_bytes(&msg, sizeof(msg));
}

std::span<const uint8_t> Sender::wire_bytes(const CookieReply& msg) {
    return as_bytes(&msg, sizeof(msg));
}

bool Sender::serialize_transport(const TransportData& msg,
                                 size_t plaintext_size,
                                 std::vector<uint8_t>& out) {
    if (plaintext_size > PAYLOAD_MAX_SIZE) {
        return false;
    }

    const size_t ciphertext_size = plaintext_size + TAG_SIZE;
    out.resize(sizeof(TransportDataHeader) + ciphertext_size);
    std::memcpy(out.data(), &msg.header, sizeof(TransportDataHeader));
    std::memcpy(out.data() + sizeof(TransportDataHeader),
                msg.encrypted_data.data(), ciphertext_size);
    return true;
}

bool Sender::cookie_is_fresh(Timestamp now) const {
    return cookie_.valid && cookie_.received_at.add_seconds(
                                config_.cookie_lifetime_seconds) > now;
}

}  // namespace wg
