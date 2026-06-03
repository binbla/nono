#ifndef UTILS_HPP
#define UTILS_HPP
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace wg::wire {

constexpr uint16_t bswap16(uint16_t v) noexcept {
    return static_cast<uint16_t>((v >> 8) | (v << 8));
}

constexpr uint32_t bswap32(uint32_t v) noexcept {
    return ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
           ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
}

constexpr uint64_t bswap64(uint64_t v) noexcept {
    return ((v & 0x00000000000000ffULL) << 56) |
           ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x0000000000ff0000ULL) << 24) |
           ((v & 0x00000000ff000000ULL) << 8) |
           ((v & 0x000000ff00000000ULL) >> 8) |
           ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x00ff000000000000ULL) >> 40) |
           ((v & 0xff00000000000000ULL) >> 56);
}

constexpr uint32_t host_to_le32(uint32_t v) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        return v;
    } else {
        return bswap32(v);
    }
}

constexpr uint64_t host_to_le64(uint64_t v) noexcept {
    if constexpr (std::endian::native == std::endian::little) {
        return v;
    } else {
        return bswap64(v);
    }
}

constexpr uint32_t le_to_host32(uint32_t v) noexcept { return host_to_le32(v); }

constexpr uint64_t le_to_host64(uint64_t v) noexcept { return host_to_le64(v); }

}  // namespace wg::wire

#endif  // UTILS_HPP