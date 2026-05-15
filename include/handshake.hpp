#ifndef HANDSHAKE_HPP
#define HANDSHAKE_HPP

#include <memory>

#include "keypair.hpp"
#include "types.hpp"

namespace wg {
enum class HandshakeState {
    Zeroed,
    CreatedInitiation,
    ConsumedInitiation,
    CreatedResponse,
    ConsumedResponse,
};
struct Handshake {
    // 当前握手状态
    HandshakeState state = HandshakeState::Zeroed;

    KeypairIndex local_index = 0;   // 本端索引
    KeypairIndex remote_index = 0;  // 对端索引：对方包里的 sender_index

    // 在clear_runtime的时候会被清空
    PrivateKey ephemeral_private{};  // 本地临时私钥
    PublicKey remote_ephemeral{};    // 对端临时公钥

    // Noise 协议的状态变量，跟握手消息的处理密切相关
    ChainingKey chaining_key{};  // ck
    Hash hash{};                 // h

        // responder 侧：记录从该 peer 收到的最新 initiation timestamp。
    // 这是长期状态，不应该在每次 clear_runtime() 时清除。
    Timestamp latest_timestamp{};

    // responder 侧：记录上一次成功消费 initiation 的本地单调时间。
    Timestamp last_initiation_consumption_ns{};

    // -------- helper --------

    void clear_runtime() {
        ephemeral_private.fill(0);
        remote_ephemeral.fill(0);
        hash.fill(0);
        chaining_key.fill(0);
        // last_mac1.fill(0);

        // latest_timestamp.clear();
        last_initiation_consumption_ns.clear();

        local_index = 0;
        remote_index = 0;
        state = HandshakeState::Zeroed;
    }

    // 这两个是固化的
    void init_for_peer(Hash base_hash, ChainingKey base_chaining_key) {
        clear_runtime();
        hash = base_hash;
        chaining_key = base_chaining_key;
    }

    bool is_zeroed() const { return state == HandshakeState::Zeroed; }
    bool is_initiation() const {
        return state == HandshakeState::CreatedInitiation ||
               state == HandshakeState::ConsumedInitiation;
    }
    bool is_response() const {
        return state == HandshakeState::CreatedResponse ||
               state == HandshakeState::ConsumedResponse;
    }
};
}  // namespace wg

#endif  // HANDSHAKE_HPP