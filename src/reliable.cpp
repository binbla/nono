#include "reliable.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <sstream>

#include "../external/kcp/ikcp.h"
#include "crypto.hpp"
#include "logger.hpp"
#include "utils.hpp"

namespace wg {
namespace {

uint32_t now_ms() {
    using Clock = std::chrono::steady_clock;
    const auto now = Clock::now().time_since_epoch();
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

}  // namespace

// ============================================================
// 协议配置
ReliableConfig ReliableConfig::normal_mode() {
    ReliableConfig config;
    config.set_nodelay(0, 40, 0, 0).set_min_rto(100);
    return config;
}

ReliableConfig ReliableConfig::fast_mode() {
    ReliableConfig config;
    config.set_nodelay(1, 10, 2, 1).set_min_rto(30);
    return config;
}

ReliableConfig& ReliableConfig::set_mtu(int mtu) {
    // KCP 的 MTU 是 KCP segment 大小；外层还要经过 Core transport AEAD，
    // 所以这里保守限制在 Core 明文负载上限内。
    mtu_ = std::clamp(mtu, 256, static_cast<int>(PAYLOAD_MAX_SIZE));
    return *this;
}

ReliableConfig& ReliableConfig::set_window(int send_window,
                                           int receive_window) {
    send_window_ = std::max(1, send_window);
    receive_window_ = std::max(1, receive_window);
    return *this;
}

ReliableConfig& ReliableConfig::set_nodelay(int nodelay, int interval_ms,
                                            int resend,
                                            int no_congestion_control) {
    nodelay_ = nodelay ? 1 : 0;
    update_interval_ms_ = std::clamp(interval_ms, 1, 1000);
    fast_resend_ = std::max(0, resend);
    no_congestion_control_ = no_congestion_control ? 1 : 0;
    return *this;
}

ReliableConfig& ReliableConfig::set_min_rto(int min_rto_ms) {
    min_rto_ms_ = std::clamp(min_rto_ms, 1, 60'000);
    return *this;
}

ReliableConfig& ReliableConfig::set_flush_after_send(bool flush) {
    flush_after_send_ = flush;
    return *this;
}

ReliableConfig& ReliableConfig::set_register_timer(bool enabled) {
    register_timer_ = enabled;
    return *this;
}
// ============================================================
void ReliableConfig::apply_to(ikcpcb* kcp) const {
    if (kcp == nullptr) {
        return;
    }

    ikcp_setmtu(kcp, mtu_);
    ikcp_wndsize(kcp, send_window_, receive_window_);
    ikcp_nodelay(kcp, nodelay_, update_interval_ms_, fast_resend_,
                 no_congestion_control_);
    kcp->rx_minrto = min_rto_ms_;
}

ReliableSession::ReliableSession(Core& core, Peer& peer, ReliableConfig config)
    : core_(core),
      peer_(peer),
      config_(config),
      conv_(derive_conv(core.local_public(), peer.remote_static())) {
    kcp_ = ikcp_create(conv_, this);
    if (kcp_ == nullptr) {
        return;
    }

    ikcp_setoutput(kcp_, &ReliableSession::output_callback);
    config_.apply_to(kcp_);

    std::ostringstream log;
    log << "KCP SESSION create conv=" << conv_ << " mtu=" << config_.mtu()
        << " snd_wnd=" << config_.send_window()
        << " rcv_wnd=" << config_.receive_window()
        << " nodelay=" << config_.nodelay()
        << " interval_ms=" << config_.update_interval_ms()
        << " fast_resend=" << config_.fast_resend()
        << " nc=" << config_.no_congestion_control()
        << " min_rto_ms=" << config_.min_rto_ms();
    Logger::default_logger().debug(log.str());
}

ReliableSession::~ReliableSession() {
    if (kcp_ != nullptr) {
        ikcp_release(kcp_);
        kcp_ = nullptr;
    }
}

ReliableSendResult ReliableSession::send(std::span<const uint8_t> message) {
    std::vector<std::vector<uint8_t>> pending;
    int rc = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (kcp_ == nullptr || message.empty()) {
            return {};
        }

        rc = ikcp_send(kcp_, reinterpret_cast<const char*>(message.data()),
                       static_cast<int>(message.size()));
        if (rc < 0) {
            Logger::default_logger().warn("KCP SEND failed");
            return {.ok = false, .kcp_result = rc};
        }

        std::ostringstream log;
        log << "KCP SEND queued conv=" << conv_
            << " message_size=" << message.size();
        Logger::default_logger().debug(log.str());

        if (config_.flush_after_send()) {
            ikcp_flush(kcp_);
        }
        pending = take_pending_output();
    }
    send_pending_output(std::move(pending));
    return {.ok = true, .kcp_result = rc};
}

bool ReliableSession::input(std::span<const uint8_t> segment) {
    std::vector<std::vector<uint8_t>> messages;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (kcp_ == nullptr || segment.empty()) {
            return false;
        }

        const int rc =
            ikcp_input(kcp_, reinterpret_cast<const char*>(segment.data()),
                       static_cast<long>(segment.size()));
        std::ostringstream log;
        log << "KCP INPUT conv=" << conv_ << " segment_size=" << segment.size()
            << " rc=" << rc;
        Logger::default_logger().debug(log.str());

        if (rc < 0) {
            return false;
        }
        messages = drain_received_messages();
    }
    deliver_messages(std::move(messages));
    return true;
}

void ReliableSession::update() {
    std::vector<std::vector<uint8_t>> pending;
    std::vector<std::vector<uint8_t>> messages;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (kcp_ == nullptr) {
            return;
        }
        ikcp_update(kcp_, now_ms());
        messages = drain_received_messages();
        pending = take_pending_output();
    }
    deliver_messages(std::move(messages));
    send_pending_output(std::move(pending));
}

void ReliableSession::flush() {
    std::vector<std::vector<uint8_t>> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (kcp_ != nullptr) {
            ikcp_flush(kcp_);
            pending = take_pending_output();
        }
    }
    send_pending_output(std::move(pending));
}

void ReliableSession::set_message_callback(MessageCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    message_callback_ = std::move(callback);
}

uint32_t ReliableSession::derive_conv(const PublicKey& local_public,
                                      const PublicKey& remote_public) {
    const PublicKey* first = &local_public;
    const PublicKey* second = &remote_public;
    if (remote_public < local_public) {
        first = &remote_public;
        second = &local_public;
    }

    std::array<uint8_t, PUBLIC_KEY_SIZE * 2 + 11> material{};
    size_t offset = 0;
    std::memcpy(material.data() + offset, first->data(), first->size());
    offset += first->size();
    std::memcpy(material.data() + offset, second->data(), second->size());
    offset += second->size();
    constexpr char kLabel[] = "nono-kcp-v1";
    std::memcpy(material.data() + offset, kLabel, sizeof(kLabel) - 1);

    Hash hash{};
    crypto::hash(material, hash);
    uint32_t conv = 0;
    std::memcpy(&conv, hash.data(), sizeof(conv));
    conv = wire::le_to_host32(conv);
    return conv == 0 ? 1 : conv;
}

int ReliableSession::output_callback(const char* buf, int len, ikcpcb*,
                                     void* user) {
    auto* session = static_cast<ReliableSession*>(user);
    if (session == nullptr || buf == nullptr || len <= 0) {
        return -1;
    }
    return session->output(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(len)));
}

std::vector<std::vector<uint8_t>> ReliableSession::drain_received_messages() {
    std::vector<std::vector<uint8_t>> messages;
    while (kcp_ != nullptr) {
        const int size = ikcp_peeksize(kcp_);
        if (size < 0) {
            return messages;
        }

        receive_buffer_.resize(static_cast<size_t>(size));
        const int rc = ikcp_recv(
            kcp_, reinterpret_cast<char*>(receive_buffer_.data()), size);
        if (rc < 0) {
            return messages;
        }

        std::ostringstream log;
        log << "KCP RECV conv=" << conv_ << " message_size=" << rc;
        Logger::default_logger().debug(log.str());

        messages.emplace_back(receive_buffer_.begin(),
                              receive_buffer_.begin() + rc);
    }
    return messages;
}

void ReliableSession::deliver_messages(
    std::vector<std::vector<uint8_t>> messages) {
    MessageCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = message_callback_;
    }
    if (!callback) {
        return;
    }

    for (const std::vector<uint8_t>& message : messages) {
        callback(peer_,
                 std::span<const uint8_t>(message.data(), message.size()));
    }
}

std::vector<std::vector<uint8_t>> ReliableSession::take_pending_output() {
    std::vector<std::vector<uint8_t>> out;
    out.swap(pending_output_);
    return out;
}

void ReliableSession::send_pending_output(
    std::vector<std::vector<uint8_t>> segments) {
    for (const std::vector<uint8_t>& segment : segments) {
        std::ostringstream log;
        log << "KCP OUTPUT conv=" << conv_
            << " segment_size=" << segment.size();
        Logger::default_logger().debug(log.str());
        core_.send_to_peer(peer_, {segment.data(), segment.size()});
    }
}

int ReliableSession::output(std::span<const uint8_t> segment) {
    pending_output_.emplace_back(segment.begin(), segment.end());
    return 0;
}

ReliableManager::ReliableManager(Core& core, ReliableConfig config)
    : core_(core), config_(config) {
    core_.set_packet_callback(
        [this](Peer& peer, std::span<const uint8_t> data) {
            input(peer, data);
        });

    if (config_.register_timer()) {
        core_.timers().schedule_every(
            std::chrono::milliseconds(config_.update_interval_ms()),
            [this] { update_all(); }, "kcp.update", true);
    }
}

ReliableSession& ReliableManager::session_for(Peer& peer) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(peer.remote_static());
    if (it != sessions_.end()) {
        return *it->second;
    }

    auto session = std::make_unique<ReliableSession>(core_, peer, config_);
    session->set_message_callback(message_callback_);
    ReliableSession& ref = *session;
    sessions_.emplace(peer.remote_static(), std::move(session));
    return ref;
}

ReliableSendResult ReliableManager::send(Peer& peer,
                                         std::span<const uint8_t> message) {
    return session_for(peer).send(message);
}

ReliableSendResult ReliableManager::send(const PublicKey& remote_static,
                                         std::span<const uint8_t> message) {
    Peer* peer = core_.find_peer(remote_static);
    if (peer == nullptr) {
        return {};
    }
    return send(*peer, message);
}

void ReliableManager::input(Peer& peer, std::span<const uint8_t> segment) {
    session_for(peer).input(segment);
}

void ReliableManager::update_all() {
    std::vector<ReliableSession*> sessions;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions.reserve(sessions_.size());
        for (auto& [_, session] : sessions_) {
            sessions.push_back(session.get());
        }
    }

    for (ReliableSession* session : sessions) {
        if (session != nullptr) {
            session->update();
        }
    }
}

void ReliableManager::set_message_callback(MessageCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    message_callback_ = std::move(callback);
    for (auto& [_, session] : sessions_) {
        session->set_message_callback(message_callback_);
    }
}

}  // namespace wg
