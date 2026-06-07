#ifndef RELIABLE_HPP
#define RELIABLE_HPP
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

#include "core.hpp"
#include "peer.hpp"
#include "types.hpp"

struct IKCPCB;
typedef struct IKCPCB ikcpcb;

namespace wg {

class ReliableConfig {
   public:
    // 普通模式：ikcp_nodelay(kcp, 0, 40, 0, 0)
    static ReliableConfig normal_mode();

    // 极速模式：ikcp_nodelay(kcp, 1, 10, 2, 1)
    static ReliableConfig fast_mode();

    // KCP segment 会作为 Core transport 明文发送，所以 MTU 必须小于
    // PAYLOAD_MAX_SIZE。
    ReliableConfig& set_mtu(int mtu);
    ReliableConfig& set_window(int send_window, int receive_window);
    ReliableConfig& set_nodelay(int nodelay, int interval_ms, int resend,
                                int no_congestion_control);
    ReliableConfig& set_min_rto(int min_rto_ms);
    ReliableConfig& set_flush_after_send(bool flush);
    ReliableConfig& set_register_timer(bool enabled);

    int mtu() const { return mtu_; }
    int send_window() const { return send_window_; }
    int receive_window() const { return receive_window_; }
    int nodelay() const { return nodelay_; }
    int update_interval_ms() const { return update_interval_ms_; }
    int fast_resend() const { return fast_resend_; }
    int no_congestion_control() const { return no_congestion_control_; }
    int min_rto_ms() const { return min_rto_ms_; }
    bool flush_after_send() const { return flush_after_send_; }
    bool register_timer() const { return register_timer_; }

    void apply_to(ikcpcb* kcp) const;

   private:
    int mtu_ = 1200;
    int send_window_ = 128;
    int receive_window_ = 128;

    int nodelay_ = 1;
    int update_interval_ms_ = 20;
    int fast_resend_ = 2;
    int no_congestion_control_ = 1;

    // KCP 默认普通模式约 100ms，快速模式通常降到 30ms；这里默认 30ms。
    int min_rto_ms_ = 30;

    bool flush_after_send_ = true;
    bool register_timer_ = true;
};

struct ReliableSendResult {
    bool ok = false;
    int kcp_result = 0;
};

// ReliableSession 是单个 peer 上的 KCP 会话。
//
// 它不拥有 Core/Peer，只把 KCP output 回调接到 Core::send_to_peer()。
// Core 仍然只处理可信 datagram，可靠性状态完全留在本层。
class ReliableSession {
   public:
    using MessageCallback =
        std::function<void(Peer& peer, std::span<const uint8_t> message)>;

    ReliableSession(Core& core, Peer& peer, ReliableConfig config = {});
    ~ReliableSession();

    ReliableSession(const ReliableSession&) = delete;
    ReliableSession& operator=(const ReliableSession&) = delete;

    ReliableSession(ReliableSession&&) = delete;
    ReliableSession& operator=(ReliableSession&&) = delete;

    ReliableSendResult send(std::span<const uint8_t> message);
    bool input(std::span<const uint8_t> segment);
    void update();
    void flush();

    Peer& peer() { return peer_; }
    const Peer& peer() const { return peer_; }
    uint32_t conv() const { return conv_; }

    void set_message_callback(MessageCallback callback);

    static uint32_t derive_conv(const PublicKey& local_public,
                                const PublicKey& remote_public);

   private:
    static int output_callback(const char* buf, int len, ikcpcb* kcp,
                               void* user);

    std::vector<std::vector<uint8_t>> drain_received_messages();
    void deliver_messages(std::vector<std::vector<uint8_t>> messages);
    std::vector<std::vector<uint8_t>> take_pending_output();
    void send_pending_output(std::vector<std::vector<uint8_t>> segments);
    int output(std::span<const uint8_t> segment);

    Core& core_;
    Peer& peer_;
    ReliableConfig config_;
    ikcpcb* kcp_ = nullptr;
    uint32_t conv_ = 0;
    MessageCallback message_callback_;
    std::vector<uint8_t> receive_buffer_;
    std::vector<std::vector<uint8_t>> pending_output_;
    std::mutex mutex_;
};

// ReliableManager 管理多个 peer 的 ReliableSession，并接管 Core 的明文回调。
class ReliableManager {
   public:
    using MessageCallback = ReliableSession::MessageCallback;

    explicit ReliableManager(Core& core, ReliableConfig config = {});
    ~ReliableManager() = default;

    ReliableManager(const ReliableManager&) = delete;
    ReliableManager& operator=(const ReliableManager&) = delete;

    ReliableSession& session_for(Peer& peer);
    ReliableSendResult send(Peer& peer, std::span<const uint8_t> message);
    ReliableSendResult send(const PublicKey& remote_static,
                            std::span<const uint8_t> message);

    void input(Peer& peer, std::span<const uint8_t> segment);
    void update_all();

    void set_message_callback(MessageCallback callback);

   private:
    Core& core_;
    ReliableConfig config_;
    MessageCallback message_callback_;
    std::map<PublicKey, std::unique_ptr<ReliableSession>> sessions_;
    std::mutex mutex_;
};

}  // namespace wg

#endif  // RELIABLE_HPP
