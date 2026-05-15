#ifndef KEYPAIR_HPP
#define KEYPAIR_HPP
#include <array>
#include <atomic>
#include <cstdint>

#include "crypto.hpp"
#include "replay_counter.hpp"
#include "tai64n.hpp"
#include "types.hpp"

namespace wg {
class Peer;
class Keypair {
    /*
    Keypair 指定了一个session
    key的生命周期和状态，包含发送和接收两个方向的密钥，以及相关的计数器和索引信息。
    它是Noise协议中一个重要的抽象，用于管理会话密钥的更新和过期。
    */
   public:
    Keypair() = default;

    ~Keypair() {
        crypto::secure_zero(sending_);
        crypto::secure_zero(receiving_);
    }
    Keypair(const Keypair&) = delete;
    Keypair& operator=(const Keypair&) = delete;

    Keypair(Keypair&&) = delete;
    Keypair& operator=(Keypair&&) = delete;

    // 两端的索引
    KeypairIndex local_index = 0;
    KeypairIndex remote_index = 0;
    // 所属peer
    Peer* owner = nullptr;
    // 状态和计数器
    Timestamp created_at;    // keypair 创建时间，单位 ns
    Timestamp last_used_at;  // keypair 最后一次使用时间，单位 ns

    std::atomic<uint64_t> sending_counter = 0;
    std::atomic<uint64_t> receiving_counter = 0;

    // 是否是发起者
    bool i_am_the_initiator = false;
    bool is_activated = false;  // 标识这个keypair是否可以发送

   public:
    // 发送和接收的对称密钥
    const SymmetricKey& sending() const { return sending_; }
    const SymmetricKey& receiving() const { return receiving_; }
    // set
    void set_sending(const SymmetricKey& key) { sending_ = key; }
    void set_receiving(const SymmetricKey& key) { receiving_ = key; }

    bool check_replay(uint64_t counter) { return replay_.check(counter); }

   private:
    // 只有密钥需要安全清零和设置一个读取和写入的接口，其他成员不需要
    SymmetricKey sending_;
    SymmetricKey receiving_;

    ReplayCounter replay_;
};

}  // namespace wg
#endif  // KEYPAIR_HPP
