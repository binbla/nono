#include "protocol.hpp"

#include "index_table.hpp"
#include "noise.hpp"
#include "types.hpp"

namespace wg {
namespace {

Nonce nonce_from_counter(uint64_t counter) {
    Nonce nonce{};

    // WireGuard transport nonce: 32-bit zero prefix + 64-bit little-endian
    // packet counter. The same counter is carried in TransportDataHeader.
    for (size_t i = 0; i < COUNTER_SIZE; ++i) {
        nonce[4 + i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xff);
    }

    return nonce;
}

bool reserve_sending_counter(Keypair& keypair, uint64_t& counter) {
    counter = keypair.sending_counter.load(std::memory_order_relaxed);
    while (counter < REJECT_AFTER_MESSAGES) {
        if (keypair.sending_counter.compare_exchange_weak(
                counter, counter + 1, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return true;
        }
    }

    return false;
}

}  // namespace

// 预计算 base_chaining_key 和 base_hash
bool NoiseProtocol::initialize(const PrivateKey& local_private,
                               const PublicKey& local_public) {
    // 初始化本地长期密钥对和预计算的 base_chaining_key / base_hash
    local_private_ = local_private;
    local_public_ = local_public;

    if (!wg::noise::initialize_base(base_chaining_key_, base_hash_,
                                    base_hash_self_, local_public_)) {
        return false;
    }
    // 用作生成cookie的预计算材料，等价于 HASH(kCookieLabel || S^{pub})
    std::span<const uint8_t> mac1_label_span(
        reinterpret_cast<const uint8_t*>(kMac1Label), sizeof(kMac1Label) - 1);
    std::span<const uint8_t> cookie_label_span(
        reinterpret_cast<const uint8_t*>(kCookieLabel),
        sizeof(kCookieLabel) - 1);

    crypto::hash_concat(mac1_label_span, local_public_,
                        precomputed_mac1_hash_self_);
    crypto::hash_concat(cookie_label_span, local_public_,
                        precomputed_mac2_hash_self_);
    crypto::fill_random(secret_for_cookie_);  // 定时轮转

    initialized_ = true;
    return true;
}

// 生成新的本地静态身份
bool NoiseProtocol::generate_identity(PrivateKey& out_private,
                                      PublicKey& out_public) {
    return wg::crypto::generate_static_keypair(out_private, out_public);
}

void NoiseProtocol::clear() {
    wg::crypto::secure_zero(local_private_);
    wg::crypto::secure_zero(local_public_);
    wg::crypto::secure_zero(base_chaining_key_);
    wg::crypto::secure_zero(base_hash_);
    wg::crypto::secure_zero(base_hash_self_);
    wg::crypto::secure_zero(precomputed_mac1_hash_self_);
    wg::crypto::secure_zero(precomputed_mac2_hash_self_);
    wg::crypto::secure_zero(secret_for_cookie_);
    initialized_ = false;
}

NoiseProtocol::~NoiseProtocol() { clear(); }

// ================================================================
// NoiseProtocol::handshake initiater
// ================================================================
bool NoiseProtocol::create_initiation(Peer& peer, Keypair& keypair,
                                      HandshakeInitiation& msg) {
    // 初始化消息头
    msg.message_type = MessageType::HandshakeInitiation;
    msg.sender_index = keypair.local_index;
    msg.ephemeral_public.fill(0);
    msg.static_encrypted.fill(0);
    msg.timestamp_encrypted.fill(0);
    msg.mac1.fill(0);  // 这个交给上层去算
    msg.mac2.fill(0);
    // 临时变量
    Handshake& hs = peer.handshake();
    ChainingKey chaining_key = base_chaining_key_;
    Hash hash = peer.base_hash_peer();  // 对方的
    PrivateKey ephemeral_private{};
    SymmetricKey key{};

    // handshake 清空
    hs.clear_runtime();
    // generate ephemeral keypair
    crypto::generate_ephemeral_keypair(ephemeral_private, msg.ephemeral_public);
    // e
    noise::mix_ephemeral(msg.ephemeral_public, chaining_key, hash);
    // es
    noise::mix_dh(chaining_key, key, ephemeral_private, peer.remote_static());
    // s
    noise::encrypt_and_hash(msg.static_encrypted, local_public_, key, hash);
    // ss
    noise::mix_precomputed_dh(chaining_key, key,
                              peer.precomputed_static_static());
    // timestamp
    noise::encrypt_and_hash(msg.timestamp_encrypted, keypair.created_at.bytes(),
                            key, hash);
    // 后处理
    crypto::secure_zero(key);
    // 保存握手状态
    hs.ephemeral_private = ephemeral_private;
    hs.local_index = keypair.local_index;
    hs.state = HandshakeState::CreatedInitiation;
    hs.latest_timestamp = keypair.created_at;

    return true;
}

Peer* NoiseProtocol::consume_initiation(const HandshakeInitiation& msg,
                                        PeerManager& peers) {
    /*
    消费握手消息
    1. 首先是解析消息，拿到对应的信息。证明消息的正确性
    2. handshake必须是清空的。
    3. 消费完后更新状态
     */
    if (!initialized_) {
        return nullptr;
    }

    // 临时变量
    ChainingKey chaining_key = base_chaining_key_;
    Hash hash = base_hash_self_;  // comsume的时候用自己的
    PublicKey ephemeral_public{};
    SymmetricKey key{};
    PublicKey remote_static{};
    Timestamp timestamp{};

    // 1. 获取 msg.ephemeral
    ephemeral_public = msg.ephemeral_public;

    // e
    noise::mix_ephemeral(ephemeral_public, chaining_key, hash);
    // es
    noise::mix_dh(chaining_key, key, local_private_, ephemeral_public);
    // s (不可信任，来自网络，验证后才能用)
    if (!noise::decrypt_and_hash(remote_static, msg.static_encrypted, key,
                                 hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }
    // 找到peer
    Peer* peer = peers.find_by_public_key(remote_static);
    if (!peer) {
        crypto::secure_zero(key);
        return nullptr;
    }
    //
    noise::mix_precomputed_dh(chaining_key, key,
                              peer->precomputed_static_static());
    // timestamp（不可信任，来自网络，验证后才能用）
    if (!noise::decrypt_and_hash(timestamp.bytes(), msg.timestamp_encrypted,
                                 key, hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    Handshake& hs = peer->handshake();
    Timestamp now_ns = Timestamp::now();

    // replay / flood 检查
    bool replay_attack = (timestamp <= hs.latest_timestamp);
    bool flood_attack =
        (hs.last_initiation_consumption_ns + kInitiationMinInterval > now_ns);
    if (replay_attack || flood_attack) {
        crypto::secure_zero(key);
        return nullptr;
    }
    // 后处理
    crypto::secure_zero(key);

    // 更新握手状态
    hs.clear_runtime();  // 清空旧的握手状态
    hs.remote_ephemeral = ephemeral_public;
    hs.latest_timestamp = timestamp;  // init方的创建时间
    hs.remote_index = msg.sender_index;
    hs.last_initiation_consumption_ns = now_ns;  // 消费 initiation 的时间
    hs.state = HandshakeState::ConsumedInitiation;

    return peer;
}
// ================================================================
// NoiseProtocol::handshake responder
// ================================================================
bool NoiseProtocol::create_response(Peer& peer, Keypair& keypair,
                                    HandshakeResponse& msg) {
    /*
    创建握手响应消息
    1. 确认状态：handshake必须是ConsumedInitiation状态
    2. keypair是新分配的，这里不管。
    3. 创建响应消息，更新握手状态
     */

    // 临时变量
    Handshake& hs = peer.handshake();
    ChainingKey chaining_key = base_chaining_key_;
    Hash hash = peer.base_hash_peer();  // create response的时候用对方的
    PrivateKey ephemeral_private{};
    SymmetricKey key{};
    SymmetricKey sending{};
    SymmetricKey receiving{};
    // 检查状态
    if (!initialized_ ||
        (hs.state != HandshakeState::ConsumedInitiation &&
         hs.state != HandshakeState::CreatedResponse) ||
        hs.remote_index == 0 || crypto::is_all_zero(hs.remote_ephemeral)) {
        return false;
    }
    // 初始化消息头
    msg.message_type = MessageType::HandshakeResponse;
    msg.sender_index = keypair.local_index;
    msg.receiver_index = hs.remote_index;
    msg.ephemeral_public.fill(0);  // 明文
    msg.empty_encrypted.fill(0);
    msg.mac1.fill(0);
    msg.mac2.fill(0);

    // gen ephemeral keypair
    crypto::generate_ephemeral_keypair(ephemeral_private, msg.ephemeral_public);
    // e
    noise::mix_ephemeral(msg.ephemeral_public, chaining_key, hash);
    // ee
    noise::mix_dh(chaining_key, key, ephemeral_private, hs.remote_ephemeral);
    // es
    noise::mix_dh(chaining_key, key, ephemeral_private, peer.remote_static());
    // psk
    noise::mix_psk(chaining_key, hash, key, peer.preshared_key());
    // encrypt_and_hash 空消息
    noise::encrypt_and_hash(msg.empty_encrypted,
                            /*plaintext=*/{}, key, hash);
    // 派生对称密钥
    noise::derive_transport_keys(chaining_key, receiving, sending);
    // 后处理
    crypto::secure_zero(key);

    keypair.remote_index = hs.remote_index;
    keypair.set_sending(sending);
    keypair.set_receiving(receiving);
    // keypair.is_activated = true; // 要收到第一条消息才激活
    crypto::secure_zero(sending);
    crypto::secure_zero(receiving);
    crypto::secure_zero(chaining_key);

    // 更新握手状态
    hs.ephemeral_private = ephemeral_private;
    hs.local_index = keypair.local_index;
    hs.state = HandshakeState::CreatedResponse;
    return true;
}

Peer* NoiseProtocol::consume_response(const HandshakeResponse& msg,
                                      PeerManager& peers,
                                      IndexTable& index_table) {
    /*
    消费握手响应消息
    1. 首先是解析消息，拿到对应的信息。证明消息的正确
    2. 判断keypair存在且未激活
    3. handshake状态正确且index对得上
    4. 消费完后更新状态
    */
    if (!initialized_) {
        return nullptr;
    }
    // 临时变量
    ChainingKey chaining_key;
    Hash hash;
    KeypairIndex remote_index;
    PublicKey remote_ephemeral;
    Peer* peer;
    SymmetricKey key{};
    std::array<uint8_t, 0> empty{};
    SymmetricKey sending{};
    SymmetricKey receiving{};

    // 1. 找到对应的keypair和对方生成的ephemeral key
    Keypair* keypair = index_table.find(msg.receiver_index);
    if (!keypair) {
        return nullptr;
    }
    // 检查keypair的正确性
    if (keypair->is_activated) {
        return nullptr;
    }
    // 检查handshake的正确性
    peer = keypair->owner;
    Handshake& hs = peer->handshake();

    if (hs.state != HandshakeState::CreatedInitiation ||
        hs.local_index != msg.receiver_index) {
        return nullptr;
    }

    // 解析消息内容
    remote_index = msg.sender_index;
    remote_ephemeral = msg.ephemeral_public;
    chaining_key = base_chaining_key_;
    hash = base_hash_self_;  // comsume 的时候用自己的

    // e
    noise::mix_ephemeral(msg.ephemeral_public, chaining_key, hash);
    // ee
    noise::mix_dh(chaining_key, key, hs.ephemeral_private, remote_ephemeral);
    // es
    noise::mix_dh(chaining_key, key, local_private_,  // Spriv_i
                  remote_ephemeral);
    // psk
    noise::mix_psk(chaining_key, hash, key, peer->preshared_key());
    // decrypt_and_hash 空消息，验证消息的正确性(数据来自网络，不可信任)
    if (!noise::decrypt_and_hash(empty, msg.empty_encrypted, key, hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }
    // 派生对称密钥
    noise::derive_transport_keys(chaining_key, sending, receiving);
    // 后处理
    crypto::secure_zero(key);

    keypair->remote_index = remote_index;
    keypair->set_sending(sending);
    keypair->set_receiving(receiving);
    keypair->is_activated = true;  // 握手完成，直接激活，允许发送和接收
    crypto::secure_zero(sending);
    crypto::secure_zero(receiving);
    crypto::secure_zero(chaining_key);

    // 7. 更新握手状态
    hs.remote_index = remote_index;
    hs.remote_ephemeral = remote_ephemeral;
    hs.state = HandshakeState::ConsumedResponse;
    return peer;
}

// ================================================================
// NoiseProtocol::data transport
// ================================================================
// 上层自己要保证传入的参数合法且足够
bool NoiseProtocol::create_datatrans(Keypair& keypair,
                                     std::span<const uint8_t> data,
                                     TransportData& msg) {
    uint64_t counter = 0;
    if (!reserve_sending_counter(keypair, counter)) {
        return false;
    }

    // 初始化消息头
    msg.header.message_type = MessageType::TransportData;
    msg.header.reserved[0] = 0;
    msg.header.reserved[1] = 0;
    msg.header.reserved[2] = 0;
    msg.header.receiver_index = keypair.remote_index;
    msg.header.counter = counter;
    msg.encrypted_data.fill(0);

    Nonce nonce = nonce_from_counter(counter);

    const size_t ciphertext_size = data.size() + TAG_SIZE;
    std::span<uint8_t> ciphertext(msg.encrypted_data.data(), ciphertext_size);
    // 使用对称密钥加密数据(自信任上层传入的参数)
    crypto::aead_encrypt(keypair.sending(), nonce,
                         /*ad=*/std::span<const uint8_t>{}, data, ciphertext);

    keypair.last_used_at = Timestamp::now();
    return true;
}

// 作为协议底层，直接相信上层传入的参数合法且足够
bool NoiseProtocol::consume_datatrans(IndexTable& index_table,
                                      const TransportData& msg,
                                      std::span<uint8_t> data) {
    if (!initialized_) {
        return false;
    }
    Keypair* keypair = index_table.find(msg.header.receiver_index);
    if (keypair == nullptr) {
        return false;
    }
    // 已激活则跳过检查
    if (keypair->is_activated) {
        // 已激活，无需处理
    } else if (keypair->i_am_the_initiator) {
        // 发起方不应该处于未激活状态
        return false;
    } else {
        // 响应方：需要收到第一条数据消息才能激活
        const Handshake& hs = keypair->owner->handshake();
        if (hs.state != HandshakeState::CreatedResponse ||
            hs.local_index != msg.header.receiver_index) {
            return false;
        }
    }

    const size_t ciphertext_size = data.size() + TAG_SIZE;
    std::span<const uint8_t> ciphertext(msg.encrypted_data.data(),
                                        ciphertext_size);
    const Nonce nonce = nonce_from_counter(msg.header.counter);
    // 使用对称密钥解密数据（数据来自网络，不可信任）
    if (!crypto::aead_decrypt(keypair->receiving(), nonce,
                              /*ad=*/std::span<const uint8_t>{}, ciphertext,
                              data)) {
        return false;
    }

    // 只有认证成功的包才能提交 replay 窗口，避免伪造包污染状态。
    if (!keypair->check_replay(msg.header.counter)) {
        crypto::secure_zero(data);
        return false;
    }
    keypair->is_activated = true;

    // keypair->last_used_at = Timestamp::now(); // 这个让send/receive自己更新
    return true;
}

// 定时轮转 secret_for_cookie
// 注册给周期计时器就行
void NoiseProtocol::rotate_secret_for_cookie() {
    Bytes32 next_secret{};
    if (!crypto::fill_random(next_secret)) {
        return;
    }

    crypto::secure_zero(secret_for_cookie_);
    secret_for_cookie_ = next_secret;
    crypto::secure_zero(next_secret);
}

}  // namespace wg
