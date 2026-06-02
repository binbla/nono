#ifndef LOAD_MONITOR_HPP
#define LOAD_MONITOR_HPP
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace wg {

struct LoadMonitorConfig {
    // 单秒内握手包数量超过该阈值后，要求后续握手带有效 mac2。
    size_t handshake_per_second_limit = 64;

    // 单秒内总 UDP 包数量超过该阈值后，也进入 mac2 强制验证模式。
    size_t packet_per_second_limit = 4096;

    // 触发高负载后保持多久。这样负载刚回落时不会立刻反复抖动。
    std::chrono::seconds overload_hold_time{5};
};

struct LoadSnapshot {
    size_t packets_this_second = 0;
    size_t handshakes_this_second = 0;
    bool needs_mac2 = false;
};

class LoadMonitor {
    // LoadMonitor 是 receive 层的负载判断模块。
    // 它不处理 packet 内容，只统计“最近这一秒有多少包/握手”。
    //
    // 使用方式：
    // - 收到任意 UDP 包后调用 observe_packet()
    // - 识别出 handshake initiation/response 后调用 observe_handshake()
    // - 验证握手消息前调用 needs_mac2_validation()
   public:
    explicit LoadMonitor(LoadMonitorConfig config = LoadMonitorConfig{})
        : config_(config), window_started_at_(Clock::now()) {}

    void observe_packet() { observe(/*is_handshake=*/false); }

    void observe_handshake() { observe(/*is_handshake=*/true); }

    bool needs_mac2_validation() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return Clock::now() < overloaded_until_;
    }

    LoadSnapshot snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return LoadSnapshot{
            .packets_this_second = packets_this_second_,
            .handshakes_this_second = handshakes_this_second_,
            .needs_mac2 = Clock::now() < overloaded_until_,
        };
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        packets_this_second_ = 0;
        handshakes_this_second_ = 0;
        window_started_at_ = Clock::now();
        overloaded_until_ = TimePoint{};
    }

   private:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    void observe(bool is_handshake) {
        std::lock_guard<std::mutex> lock(mutex_);
        const TimePoint now = Clock::now();
        rotate_window_if_needed(now);

        ++packets_this_second_;
        if (is_handshake) {
            ++handshakes_this_second_;
        }

        if (packets_this_second_ > config_.packet_per_second_limit ||
            handshakes_this_second_ > config_.handshake_per_second_limit) {
            overloaded_until_ = now + config_.overload_hold_time;
        }
    }

    void rotate_window_if_needed(TimePoint now) {
        if (now - window_started_at_ < std::chrono::seconds(1)) {
            return;
        }

        packets_this_second_ = 0;
        handshakes_this_second_ = 0;
        window_started_at_ = now;
    }

    LoadMonitorConfig config_{};

    mutable std::mutex mutex_;
    size_t packets_this_second_ = 0;
    size_t handshakes_this_second_ = 0;
    TimePoint window_started_at_{};
    TimePoint overloaded_until_{};
};

}  // namespace wg

#endif  // LOAD_MONITOR_HPP
