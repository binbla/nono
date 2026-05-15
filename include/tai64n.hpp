#ifndef TAI64N_HPP
#define TAI64N_HPP
#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>

#include "types.hpp"

namespace wg {

constexpr uint64_t TAI64N_OFFSET = 0x400000000000000aULL;  // WireGuard 偏移
constexpr uint32_t NSEC_PER_SEC = 1'000'000'000U;

/// @brief TAI64N 时间戳类
///
/// 提供秒级精度的 TAI64N 时间戳表示和操作，支持从系统时间生成、
/// 时间戳比较和差值计算。时间戳采用 12 字节大端格式存储：
/// 前 8 字节为秒数（TAI64 格式），后 4 字节为纳秒数。
class Timestamp {
   public:
    Timestamp() { data_.fill(0); }
    explicit Timestamp(const std::array<uint8_t, TIMESTAMP_SIZE>& bytes)
        : data_(bytes) {}

    static Timestamp zero() { return Timestamp(); }

    // 从系统时间生成当前 timestamp
    static Timestamp now() {
        Timestamp ts;
        auto now = std::chrono::system_clock::now();
        auto since_epoch = now.time_since_epoch();

        uint64_t sec = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(since_epoch)
                .count());
        uint32_t nsec = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                since_epoch -
                std::chrono::duration_cast<std::chrono::seconds>(since_epoch))
                .count());

        // 加上 WireGuard 偏移
        uint64_t tai_sec = TAI64N_OFFSET + sec;

        ts.set_parts(tai_sec, nsec);
        return ts;
    }

    // 比较操作
    bool operator>(const Timestamp& other) const {
        return to_uint64_sec() > other.to_uint64_sec() ||
               (to_uint64_sec() == other.to_uint64_sec() &&
                to_uint32_nsec() > other.to_uint32_nsec());
    }

    bool operator<(const Timestamp& other) const {
        return to_uint64_sec() < other.to_uint64_sec() ||
               (to_uint64_sec() == other.to_uint64_sec() &&
                to_uint32_nsec() < other.to_uint32_nsec());
    }

    bool operator==(const Timestamp& other) const {
        return data_ == other.data_;
    }

    bool operator>=(const Timestamp& other) const {
        return *this > other || *this == other;
    }

    bool operator<=(const Timestamp& other) const {
        return *this < other || *this == other;
    }

    // 差值，返回秒数
    double diff_seconds(const Timestamp& other) const {
        int64_t sec_diff = static_cast<int64_t>(other.tai_seconds()) -
                           static_cast<int64_t>(tai_seconds());
        int32_t nsec_diff = static_cast<int32_t>(other.nanoseconds()) -
                            static_cast<int32_t>(nanoseconds());
        return sec_diff + nsec_diff / 1e9;
    }

    static Timestamp from_bytes(
        const std::array<uint8_t, TIMESTAMP_SIZE>& bytes) {
        return Timestamp(bytes);
    }

    // 返回加上指定秒数后的新 Timestamp，不修改当前对象。
    Timestamp add_seconds(uint64_t seconds) const {
        Timestamp ts;
        ts.set_parts(tai_seconds() + seconds, nanoseconds());
        return ts;
    }

    Timestamp operator+(uint64_t seconds) const {
        return add_seconds(seconds);
    }

    Timestamp& operator+=(uint64_t seconds) {
        set_parts(tai_seconds() + seconds, nanoseconds());
        return *this;
    }

    Timestamp operator+(std::chrono::seconds interval) const {
        return add_interval(interval);
    }

    Timestamp& operator+=(std::chrono::seconds interval) {
        *this = add_interval(interval);
        return *this;
    }

    std::array<uint8_t, TIMESTAMP_SIZE>& bytes() { return data_; }

    // TAI64 部分的原始秒数，包含 WireGuard/TAI64N 偏移。
    uint64_t tai_seconds() const { return to_uint64_sec(); }

    // Unix epoch 秒数，去掉 TAI64N_OFFSET。零值 timestamp 返回 0。
    uint64_t unix_seconds() const {
        const uint64_t sec = tai_seconds();
        return sec >= TAI64N_OFFSET ? sec - TAI64N_OFFSET : 0;
    }

    uint32_t nanoseconds() const { return to_uint32_nsec(); }

    bool is_zero() const {
        for (uint8_t byte : data_) {
            if (byte != 0) {
                return false;
            }
        }
        return true;
    }

    void clear() { data_.fill(0); }

   private:
    std::array<uint8_t, TIMESTAMP_SIZE> data_;

    uint64_t to_uint64_sec() const {
        uint64_t sec = 0;
        for (size_t i = 0; i < 8; ++i) {
            sec = (sec << 8) | data_[i];
        }
        return sec;
    }

    uint32_t to_uint32_nsec() const {
        uint32_t nsec = 0;
        for (size_t i = 0; i < 4; ++i) {
            nsec = (nsec << 8) | data_[8 + i];
        }
        return nsec;
    }

    void set_parts(uint64_t tai_sec, uint32_t nsec) {
        for (size_t i = 0; i < 8; ++i) {
            data_[7 - i] = static_cast<uint8_t>(tai_sec & 0xFF);
            tai_sec >>= 8;
        }
        for (size_t i = 0; i < 4; ++i) {
            data_[11 - i] = static_cast<uint8_t>(nsec & 0xFF);
            nsec >>= 8;
        }
    }

    Timestamp add_interval(std::chrono::seconds interval) const {
        const int64_t seconds = interval.count();
        if (seconds >= 0) {
            return add_seconds(static_cast<uint64_t>(seconds));
        }

        const uint64_t delta =
            seconds == std::numeric_limits<int64_t>::min()
                ? static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1
                : static_cast<uint64_t>(-seconds);
        const uint64_t current = tai_seconds();
        Timestamp ts;
        ts.set_parts(current > delta ? current - delta : 0, nanoseconds());
        return ts;
    }
};

}  // namespace wg
#endif  // TAI64N_HPP
