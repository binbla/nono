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

bool Sender::create_initiation(NoiseProtocol& protocol, Peer& peer,
                               Keypair& keypair, HandshakeInitiation& msg) {
    // 填充协议层面消息内容
    // 填充 mac1 和 mac2
    if (!protocol.create_initiation(peer, keypair, msg)) {
        return false;
    }
    if (!fill_mac1(msg, peer.precomputed_mac1_hash())) {
        return false;
    }
    const bool has_cookie = !crypto::is_all_zero(keypair.last_cookie);
    if (has_cookie && !fill_mac2(msg, keypair.last_cookie)) {
        return false;
    }
    keypair.last_mac1 = msg.mac1;
    return true;
}

bool Sender::create_response(NoiseProtocol& protocol, Peer& peer,
                             Keypair& keypair, HandshakeResponse& msg) {
    if (!protocol.create_response(peer, keypair, msg)) {
        return false;
    }
    if (!fill_mac1(msg, peer.precomputed_mac1_hash())) {
        return false;
    }
    const bool has_cookie = !crypto::is_all_zero(keypair.last_cookie);
    if (has_cookie && !fill_mac2(msg, keypair.last_cookie)) {
        return false;
    }
    keypair.last_mac1 = msg.mac1;
    return true;
}

// 这个消息体没有放到protocol去create
// consume init 必须要提取出mac1和对方的endpoint
bool Sender::create_cookie_reply(NoiseProtocol& protocol,
                                 KeypairIndex receiver_index, const Mac& mac1,
                                 const Endpoint& dst, CookieReply& out) {
    // 初始化
    out.message_type = MessageType::CookieReply;
    out.receiver_index = receiver_index;

    // 生成随机nonce
    crypto::fill_random(out.nonce);
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
    return crypto::xaead_encrypt(protocol.precomputed_mac2_hash(), out.nonce,
                                 mac1, cookie, out.encrypted_cookie);
}

bool Sender::create_transport(NoiseProtocol& protocol, Keypair& keypair,
                              std::span<const uint8_t> plaintext,
                              TransportData& msg) {
    return protocol.create_datatrans(keypair, plaintext, msg);
}

// 握手的这两个数据包都是数据流，不需要管大小端
SendResult Sender::send_initiation(UdpSocket& socket, NoiseProtocol& protocol,
                                   Peer& peer, Keypair& keypair) {
    /*
    peer有合法的endpoint才发送握手消息
    */
    if (!peer.endpoint()) {
        return {};
    }

    HandshakeInitiation msg{};
    if (!create_initiation(protocol, peer, keypair, msg)) {
        return {};
    }

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
    if (!create_response(protocol, peer, keypair, msg)) {
        return {};
    }

    const std::span<const uint8_t> bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, *peer.endpoint());
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
    if (!create_transport(protocol, *keypair, plaintext, msg)) {
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

SendResult Sender::send_cookie_reply(UdpSocket& socket, NoiseProtocol& protocol,
                                     KeypairIndex receiver_index,
                                     const Mac& mac1, const Endpoint& dst) {
    CookieReply msg{};
    create_cookie_reply(protocol, receiver_index, mac1, dst, msg);
    const std::span<const uint8_t> bytes = wire_bytes(msg);
    const ssize_t sent = socket.send_bytes(bytes, dst);
    return {sent == static_cast<ssize_t>(bytes.size()),
            sent > 0 ? static_cast<size_t>(sent) : 0};
}
// 具体消息的序列化
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
};

}  // namespace wg
