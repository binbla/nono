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
    bool i_am_the_initiator = false;  // 针对一些特有的行为逻辑
    // 像是resp方只有收到第一条消息才能发送data
    // init方只要收到resp就能发data
    // 主要就是触发keypair 轮转那里的逻辑。
    bool is_activated = false;  // 标识这个keypair是否可以发送

   public:
    // 发送和接收的对称密钥
    const SymmetricKey& sending() const { return sending_; }
    const SymmetricKey& receiving() const { return receiving_; }
    // set
    void set_sending(const SymmetricKey& key) { sending_ = key; }
    void set_receiving(const SymmetricKey& key) { receiving_ = key; }

    bool check_replay(uint64_t counter) { return replay_.check(counter); }

    // 清理 keypair 的运行时状态，准备复用或彻底失效化。
    // 注意：这会安全清零发送/接收密钥，也会清掉 replay 窗口和计数器。
    void clear_runtime() {
        // crypto::secure_zero(sending_);
        crypto::secure_zero(receiving_);

        local_index = 0;
        remote_index = 0;
        // owner = nullptr;

        // created_at.clear();
        last_used_at.clear();

        sending_counter.store(0, std::memory_order_relaxed);
        receiving_counter.store(0, std::memory_order_relaxed);
        replay_.reset();

        // last_mac1.fill(0);
        // last_cookie.fill(0);

        i_am_the_initiator = false;
        is_activated = false;
    }

    // 判断可用性函数
    // 两个，一个是判断是否可以发送（是否有可用的keypair），一个是判断是否可以接收（握手状态和keypair状态）
    bool is_sendable() const {
        // keypair的有效性有两个判断标准：
        // 1. 时间
        // 2. package上限
        if (!is_activated) {
            return false;
        }

        Timestamp now = Timestamp::now();
        bool is_outdated = created_at.diff_seconds(now) > REKEY_AFTER_TIME;

        if (is_outdated) {
            return false;
        }

        bool is_overused = sending_counter.load(std::memory_order_relaxed) >
                           REKEY_AFTER_MESSAGES;

        if (is_overused) {
            return false;
        }
        return true;
    }

    bool is_receivable() const {
        // 接收的有效性判断标准：
        // 1. 握手状态必须是完成的
        // 2. keypair必须激活且未过期

        if (!is_activated) {
            return false;
        }

        Timestamp now = Timestamp::now();
        bool is_outdated = created_at.diff_seconds(now) > REJECT_AFTER_TIME;

        if (is_outdated) {
            return false;
        }

        bool is_overused = receiving_counter.load(std::memory_order_relaxed) >
                           REJECT_AFTER_MESSAGES;

        if (is_overused) {
            return false;
        }
        return true;
    }

   private:
    // 只有密钥需要安全清零和设置一个读取和写入的接口，其他成员不需要
    SymmetricKey sending_;
    SymmetricKey receiving_;

    ReplayCounter replay_;
};

}  // namespace wg
#endif  // KEYPAIR_HPP
