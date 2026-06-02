#ifndef UTILS_HPP
#define UTILS_HPP
#include <cstddef>
#include <span>
#include <type_traits>
template <typename T>
std::span<const uint8_t> object_prefix_bytes(const T& obj, size_t len) {
    return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&obj),
                                    len);
}
#endif  // UTILS_HPP