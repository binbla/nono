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
    if (wg::crypto::is_all_zero(local_private) ||
        wg::crypto::is_all_zero(local_public)) {
        return false;
    }
    local_private_ = local_private;
    local_public_ = local_public;

    if (!wg::noise::initialize_base(base_chaining_key_, base_hash_)) {
        return false;
    }
    // 用作生成cookie的预计算材料，等价于 HASH(kCookieLabel || S^{pub})
    std::span<const uint8_t> cookie_label_span(
        reinterpret_cast<const uint8_t*>(kCookieLabel),
        sizeof(kCookieLabel) - 1);
    std::span<const uint8_t> local_public_span(local_public_.data(),
                                               local_public_.size());

    crypto::hash_concat(cookie_label_span, local_public_span,
                        precomputed_mac2_hash_);

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
    initialized_ = false;
}

NoiseProtocol::~NoiseProtocol() { clear(); }

// ================================================================
// NoiseProtocol::handshake
// ================================================================
// Keypair 是新分配的。在此之前一定要先处理掉原来的keypair
bool NoiseProtocol::create_initiation(Peer& peer, Keypair& keypair,
                                      HandshakeInitiation& msg) {
    if (!initialized_) {
        return false;
    }
    // 初始化消息头
    msg.message_type = MessageType::HandshakeInitiation;
    msg.sender_index = keypair.local_index;
    msg.ephemeral_public.fill(0);
    msg.static_encrypted.fill(0);
    msg.timestamp_encrypted.fill(0);
    msg.mac1.fill(0);  // 这个交给上层去算
    msg.mac2.fill(0);

    // 1-3
    Handshake& hs = peer.handshake();
    hs.clear_runtime();
    hs.chaining_key = base_chaining_key_;
    hs.hash = peer.base_hash();

    // 4
    if (!crypto::generate_ephemeral_keypair(hs.ephemeral_private,     // Epriv_i
                                            msg.ephemeral_public)) {  // Epub_i
        return false;
    }

    // 5-7（mix 自己的临时公钥）
    noise::mix_ephemeral(msg.ephemeral_public, hs.chaining_key, hs.hash);

    SymmetricKey key{};
    // 8 es
    if (!noise::mix_dh(hs.chaining_key, key,
                       hs.ephemeral_private,     // Epriv_i
                       peer.remote_static())) {  // Spub_r
        crypto::secure_zero(key);
        return false;
    }

    // 9-10
    if (!noise::encrypt_and_hash(msg.static_encrypted,
                                 local_public_,  // Spub_i
                                 key, hs.hash)) {
        crypto::secure_zero(key);
        return false;
    }

    // 11 ss
    // 自己的Epriv和对方的Epub，得到的key会被后续的timestamp加密覆盖掉，不直接用于AEAD）
    if (!noise::mix_precomputed_dh(hs.chaining_key, key,
                                   peer.precomputed_static_static())) {
        crypto::secure_zero(key);
        return false;
    }

    // 12-13
    Timestamp timestamp = keypair.created_at;

    if (!noise::encrypt_and_hash(msg.timestamp_encrypted, timestamp.bytes(),
                                 key, hs.hash)) {
        crypto::secure_zero(key);
        return false;
    }

    // 保存握手状态
    hs.local_index = keypair.local_index;
    hs.state = HandshakeState::CreatedInitiation;
    crypto::secure_zero(key);
    return true;
}

Peer* NoiseProtocol::consume_initiation(const HandshakeInitiation& msg,
                                        PeerManager& peers) {
    if (!initialized_) return nullptr;

    SymmetricKey key{};
    PublicKey remote_static{};
    Timestamp timestamp{};

    // 初始化临时 hash / chaining_key
    Hash hash = base_hash_;
    ChainingKey chaining_key = base_chaining_key_;

    // 1. 获取 msg.ephemeral
    const PublicKey& ephemeral = msg.ephemeral_public;

    // mix ephemeral
    noise::mix_ephemeral(ephemeral, chaining_key, hash);

    // 2. es = DH(local_static_private, msg.ephemeral)
    if (!noise::mix_dh(chaining_key, key, local_private_, ephemeral)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // 3. 解密静态公钥 msg.static
    if (!noise::decrypt_and_hash(remote_static, msg.static_encrypted, key,
                                 hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // 4. 查找 peer
    Peer* peer = peers.find_by_public_key(remote_static);
    if (!peer) {
        crypto::secure_zero(key);
        return nullptr;
    }

    Handshake& hs = peer->handshake();

    // 5. ss = mix_precomputed_dh(peer.precomputed_static_static)
    if (!noise::mix_precomputed_dh(chaining_key, key,
                                   peer->precomputed_static_static())) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // 6. 解密 timestamp 并更新 replay/flood 防护
    if (!noise::decrypt_and_hash(timestamp.bytes(), msg.timestamp_encrypted,
                                 key, hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    Timestamp now_ns = Timestamp::now();

    // replay / flood 检查
    // 一个必须递增
    // 一个必须足够久（比如5秒）才能接受同一peer的下一次握手请求
    // 反正初始化都是0,第一次握手只要timestamp>0就能过，后续握手必须满足上面两个条件才能过
    bool replay_attack = (timestamp <= hs.latest_timestamp);
    bool flood_attack =
        (hs.last_initiation_consumption_ns + kInitiationMinInterval > now_ns);

    if (replay_attack || flood_attack) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // 7. 更新 peer.handshake 状态
    hs.remote_ephemeral = ephemeral;
    hs.chaining_key = chaining_key;
    hs.hash = hash;
    hs.latest_timestamp = timestamp;  // init方的创建时间
    hs.remote_index = msg.sender_index;
    hs.last_initiation_consumption_ns = now_ns;  // 消费 initiation 的时间
    hs.state = HandshakeState::ConsumedInitiation;

    crypto::secure_zero(key);
    return peer;
    // 上层要根据返回情况，分配一个新的keypair，并调用create_response来生成响应消息
}
// ================================================================
// NoiseProtocol::handshake responder
// ================================================================
bool NoiseProtocol::create_response(Peer& peer, Keypair& keypair,
                                    HandshakeResponse& msg) {
    if (!initialized_) {
        return false;
    }
    Handshake& hs = peer.handshake();
    // 初始化消息头
    msg.message_type = MessageType::HandshakeResponse;
    msg.sender_index = keypair.local_index;
    msg.receiver_index = hs.remote_index;
    msg.ephemeral_public.fill(0);  // 明文
    msg.empty_encrypted.fill(0);
    msg.mac1.fill(0);  // 这个交给上层去算
    msg.mac2.fill(0);

    // 1. 生成 ephemeral keypair
    if (!crypto::generate_ephemeral_keypair(hs.ephemeral_private,     // Epriv_r
                                            msg.ephemeral_public)) {  // Epub_r
        return false;
    }

    // 2. mix_ephemeral
    noise::mix_ephemeral(msg.ephemeral_public, hs.chaining_key, hs.hash);

    // 3. DH响应方的ephemeral和发起方的ephemeral ee
    SymmetricKey key{};
    if (!noise::mix_dh(hs.chaining_key, key,
                       hs.ephemeral_private,    // Epriv_r
                       hs.remote_ephemeral)) {  // Epub_i
        crypto::secure_zero(key);
        return false;
    }  // 这里输出的 k 不直接用于 AEAD，随后会被 se/psk 步骤覆盖。

    // 4. mix_dh响应方的ephemeral和发起方的静态 se
    if (!noise::mix_dh(hs.chaining_key, key,
                       hs.ephemeral_private,     // Epriv_r
                       peer.remote_static())) {  // Spub_i
        crypto::secure_zero(key);
        return false;
    }

    // 5. mix_psk 如果有预共享密钥的话 这里得到的key是要使用的
    noise::mix_psk(hs.chaining_key, hs.hash, key, peer.preshared_key());

    // 6. encrypt_and_hash 空消息
    if (!noise::encrypt_and_hash(msg.empty_encrypted,
                                 /*plaintext=*/{}, key, hs.hash)) {
        crypto::secure_zero(key);
        return false;
    }
    crypto::secure_zero(key);
    return true;
}
Peer* NoiseProtocol::consume_response(const HandshakeResponse& msg,
                                      PeerManager& peers,
                                      IndexTable& index_table) {
    if (!initialized_) return nullptr;
    (void)peers;
    // 1. 找到对应的keypair和对方生成的ephemeral key
    Keypair* keypair = index_table.find(msg.receiver_index);
    if (!keypair) {
        return nullptr;
    }
    Peer* peer = keypair->owner;
    Handshake& hs = peer->handshake();
    // 这个消息还没有经过验证，不能完全信任里面的内容，所以先不更新hs.remote_index和hs.remote_ephemeral，等验证通过后再更新

    KeypairIndex remote_index = msg.sender_index;
    PublicKey remote_ephemeral = msg.ephemeral_public;
    ChainingKey chaining_key = hs.chaining_key;
    Hash hash = hs.hash;
    // 2. mix_ephemeral
    noise::mix_ephemeral(msg.ephemeral_public, chaining_key, hash);
    // 3. mix_dh ee
    SymmetricKey key{};
    if (!noise::mix_dh(chaining_key, key,
                       hs.ephemeral_private,  // Epriv_i
                       remote_ephemeral)) {   // Epub_r
        crypto::secure_zero(key);
        return nullptr;
    }
    // 4. mix_dh se
    if (!noise::mix_dh(chaining_key, key, local_private_,  // Spriv_i
                       remote_ephemeral)) {                // Epub_r
        crypto::secure_zero(key);
        return nullptr;
    }
    // 5. mix_psk
    noise::mix_psk(chaining_key, hash, key, peer->preshared_key());
    // 6. 验证aead的tag
    std::array<uint8_t, 0> empty{};
    if (!noise::decrypt_and_hash(empty, msg.empty_encrypted, key, hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }
    // 7. 更新握手状态
    hs.chaining_key = chaining_key;
    hs.hash = hash;
    hs.remote_index = remote_index;
    hs.remote_ephemeral = remote_ephemeral;
    hs.state = HandshakeState::ConsumedResponse;
    return peer;
    // keypair 的更新交给上层
}

// ================================================================
// NoiseProtocol::data transport
// ================================================================

bool NoiseProtocol::create_datatrans(Keypair& keypair,
                                     std::span<const uint8_t> data,
                                     TransportData& msg) {
    if (!keypair.is_activated) {
        return false;
    }
    if (data.size() > PAYLOAD_MAX_SIZE) {
        return false;
    }

    uint64_t counter = 0;
    if (!reserve_sending_counter(keypair, counter)) {
        return false;
    }

    // 1. 初始化消息头
    msg.header.message_type = MessageType::TransportData;
    msg.header.reserved[0] = 0;
    msg.header.reserved[1] = 0;
    msg.header.reserved[2] = 0;
    msg.header.receiver_index = keypair.remote_index;
    // 对方只要能找到keypair就能知道是谁发的了，不需要sender_index了
    msg.header.counter = counter;

    Nonce nonce = nonce_from_counter(counter);

    msg.encrypted_data.fill(0);
    const size_t ciphertext_size = data.size() + TAG_SIZE;
    std::span<uint8_t> ciphertext(msg.encrypted_data.data(), ciphertext_size);
    if (!crypto::aead_encrypt(keypair.sending(), nonce,
                              /*ad=*/std::span<const uint8_t>{}, data,
                              ciphertext)) {
        msg.encrypted_data.fill(0);
        return false;
    }

    keypair.last_used_at = Timestamp::now();
    return true;
}

bool NoiseProtocol::consume_datatrans(IndexTable& index_table,
                                      const TransportData& msg,
                                      std::span<uint8_t> data) {
    if (data.size() > PAYLOAD_MAX_SIZE) {
        return false;
    }

    Keypair* keypair = index_table.find(msg.header.receiver_index);
    if (keypair == nullptr) {
        return false;
    }

    const size_t ciphertext_size = data.size() + TAG_SIZE;
    std::span<const uint8_t> ciphertext(msg.encrypted_data.data(),
                                        ciphertext_size);
    const Nonce nonce = nonce_from_counter(msg.header.counter);

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

    keypair->last_used_at = Timestamp::now();
    return true;
}

}  // namespace wg
