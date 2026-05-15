#ifndef ENDPOINT_HPP
#define ENDPOINT_HPP
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstring>
#include <optional>

#include "types.hpp"
namespace wg {
// Endpoint 表示一个网络通信端点，封装了 IPv4/IPv6 地址、端口和原始 sockaddr。
//
// 用法示例：
//   auto ep4 = wg::Endpoint::from_ipv4("10.0.0.1", 51820);
//   auto ep6 = wg::Endpoint::from_ipv6("2001:db8::1", 51820);
//   auto ep3 = wg::Endpoint::from_sockaddr(reinterpret_cast<const
//   sockaddr*>(addr), len);
//
// 常用场景：
// - 保存对端地址到 PeerConfig
// - 从系统调用返回的 sockaddr 转成可比较、可复制的 Endpoint
// - 读取地址族和端口号，判断两个端点是否一致
class Endpoint {
   public:
    Endpoint() : storage_{}, len_(0) {}

    // 从 IPv4 字符串和端口创建端点。
    // 失败时返回一个空端点（family 为 AF_UNSPEC，size 为 0）。
    static Endpoint from_ipv4(const char* ip, uint16_t port) {
        Endpoint endpoint;
        auto* addr = reinterpret_cast<sockaddr_in*>(&endpoint.storage_);
        addr->sin_family = AF_INET;
        addr->sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &addr->sin_addr) == 1) {
            endpoint.len_ = sizeof(sockaddr_in);
        }
        return endpoint;
    }

    // 从 IPv6 字符串和端口创建端点。
    // 失败时返回一个空端点（family 为 AF_UNSPEC，size 为 0）。
    static Endpoint from_ipv6(const char* ip, uint16_t port) {
        Endpoint endpoint;
        auto* addr = reinterpret_cast<sockaddr_in6*>(&endpoint.storage_);
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ip, &addr->sin6_addr) == 1) {
            endpoint.len_ = sizeof(sockaddr_in6);
        }
        return endpoint;
    }

    // 返回地址族，未初始化或解析失败时为 AF_UNSPEC。
    sa_family_t family() const {
        return len_ == 0 ? AF_UNSPEC : storage_.ss_family;
    }

    // 返回底层 sockaddr 指针，适合传给系统 socket API。
    const sockaddr* addr() const {
        return reinterpret_cast<const sockaddr*>(&storage_);
    }

    // 返回底层 sockaddr 的实际长度。
    socklen_t size() const { return len_; }

    // 返回端口号，未设置时返回 0。
    uint16_t port() const {
        if (family() == AF_INET && len_ >= sizeof(sockaddr_in)) {
            return ntohs(
                reinterpret_cast<const sockaddr_in*>(&storage_)->sin_port);
        }
        if (family() == AF_INET6 && len_ >= sizeof(sockaddr_in6)) {
            return ntohs(
                reinterpret_cast<const sockaddr_in6*>(&storage_)->sin6_port);
        }
        return 0;
    }

    // 比较两个端点是否完全一致，包括地址族、地址和端口。
    bool operator==(const Endpoint& other) const {
        if (family() != other.family() || len_ != other.len_) {
            return false;
        }
        if (family() == AF_INET) {
            const auto* lhs = reinterpret_cast<const sockaddr_in*>(&storage_);
            const auto* rhs =
                reinterpret_cast<const sockaddr_in*>(&other.storage_);
            return lhs->sin_port == rhs->sin_port &&
                   lhs->sin_addr.s_addr == rhs->sin_addr.s_addr;
        }
        if (family() == AF_INET6) {
            const auto* lhs = reinterpret_cast<const sockaddr_in6*>(&storage_);
            const auto* rhs =
                reinterpret_cast<const sockaddr_in6*>(&other.storage_);
            return lhs->sin6_port == rhs->sin6_port &&
                   lhs->sin6_flowinfo == rhs->sin6_flowinfo &&
                   lhs->sin6_scope_id == rhs->sin6_scope_id &&
                   std::memcmp(&lhs->sin6_addr, &rhs->sin6_addr,
                               sizeof(in6_addr)) == 0;
        }
        return std::memcmp(&storage_, &other.storage_, len_) == 0;
    }

    // 从系统返回的 sockaddr 构造端点，常用于 accept、getpeername、recvfrom
    // 等场景。
    static Endpoint from_sockaddr(const sockaddr* addr, socklen_t len) {
        Endpoint endpoint;
        if (addr == nullptr || len <= 0) {
            return endpoint;
        }

        if (addr->sa_family == AF_INET &&
            len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
            endpoint.len_ = sizeof(sockaddr_in);
        } else if (addr->sa_family == AF_INET6 &&
                   len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
            endpoint.len_ = sizeof(sockaddr_in6);
        } else {
            endpoint.len_ = len;
        }

        std::memcpy(&endpoint.storage_, addr, endpoint.len_);
        return endpoint;
    }

   private:
    sockaddr_storage storage_;
    socklen_t len_;
};

}  // namespace wg

#endif  // ENDPOINT_HPP