#ifndef SOCKET_C_HPP
#define SOCKET_C_HPP
#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#include "endpoint.hpp"

namespace wg {

class UdpSocket {
    // 非阻塞 UDP socket 的轻量 RAII 包装。
    // 只负责收发原始 datagram，不解析协议、不管理 peer。
    //
    // 使用模型：
    // - 构造 UdpSocket(port) 后，它会监听本地 [::]:port。
    // - UDP 没有真正的“连接”，向其他地址通信时直接调用 send(data, endpoint)。
    // - 如果传入 port = 0，系统会自动分配一个临时本地端口，可用 local_port()
    // 查询。
    // - 在 epoll/select/poll 发现 fd() 可读后，调用 handle_read()
    // 消费所有可读包。
    // - 后续如果需要 socket 池，可以按本地端口、地址族或网络命名空间维护多个
    // UdpSocket。
   public:
    static constexpr size_t recv_buffer_size = 2048;

    using RecvCallback =
        std::function<void(std::span<const uint8_t> data, const Endpoint& src)>;

    explicit UdpSocket(uint16_t port) { open_and_bind(port); }

    explicit UdpSocket(const Endpoint& endpoint) {
        open_and_bind_endpoint(endpoint);
    }

    ~UdpSocket() { close_if_open(); }

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    UdpSocket(UdpSocket&& other) noexcept
        : fd_(std::exchange(other.fd_, invalid_fd)),
          recv_cb_(std::move(other.recv_cb_)) {}

    UdpSocket& operator=(UdpSocket&& other) noexcept {
        if (this != &other) {
            close_if_open();
            fd_ = std::exchange(other.fd_, invalid_fd);
            recv_cb_ = std::move(other.recv_cb_);
        }
        return *this;
    }

    bool is_open() const { return fd_ >= 0; }
    int fd() const { return fd_; }

    uint16_t local_port() const {
        sockaddr_storage storage{};
        socklen_t len = sizeof(storage);
        if (!is_open() ||
            ::getsockname(fd_, reinterpret_cast<sockaddr*>(&storage), &len) <
                0) {
            return 0;
        }

        return Endpoint::from_sockaddr(
                   reinterpret_cast<const sockaddr*>(&storage), len)
            .port();
    }

    // 设置收到 UDP datagram 时的回调。
    // 回调参数：
    // - data: 收到的原始字节，只在本次回调期间有效。
    // - src: 发送方地址，可保存到 Peer.endpoint()，后续 send() 回去。
    void set_recv_callback(RecvCallback cb) { recv_cb_ = std::move(cb); }

    // UDP 发送要么发送整个 datagram，要么失败。
    // 返回 false 时可用 errno 判断原因。
    // dst 可以是 Endpoint::from_ipv4(...) / Endpoint::from_ipv6(...)
    // 得到的远端地址。
    bool send(std::span<const uint8_t> data, const Endpoint& dst) const {
        return send_bytes(data, dst) == static_cast<ssize_t>(data.size());
    }

    // 比 send() 更底层：返回 sendto 的原始结果。
    // 适合调用方想区分 EAGAIN、EMSGSIZE、ENETUNREACH 等错误的场景。
    ssize_t send_bytes(std::span<const uint8_t> data,
                       const Endpoint& dst) const {
        if (!is_open() || dst.size() == 0) {
            errno = EINVAL;
            return -1;
        }

        return ::sendto(fd_, data.data(), data.size(), 0, dst.addr(),
                        dst.size());
    }

    // epoll/select/poll 通知 fd 可读后调用。
    // callback 里的 data 只在本次回调期间有效。
    // 这个函数会一直读到 EAGAIN/EWOULDBLOCK，适合 edge-triggered epoll。
    void handle_read() {
        std::array<uint8_t, recv_buffer_size> buf{};

        while (true) {
            Endpoint src;
            const ssize_t n = recv_once(buf, src);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    return;
                }
                return;
            }

            if (n == 0) {
                continue;
            }

            if (recv_cb_) {
                recv_cb_(std::span<const uint8_t>(buf.data(),
                                                  static_cast<size_t>(n)),
                         src);
            }
        }
    }

    // 单次 recvfrom。想自己写事件循环或 socket 池调度时，可以直接用这个接口。
    ssize_t recv_once(std::span<uint8_t> buffer, Endpoint& src) const {
        if (!is_open()) {
            errno = EBADF;
            return -1;
        }
        if (buffer.empty()) {
            errno = EINVAL;
            return -1;
        }

        sockaddr_storage storage{};
        socklen_t len = sizeof(storage);
        const ssize_t n =
            ::recvfrom(fd_, buffer.data(), buffer.size(), 0,
                       reinterpret_cast<sockaddr*>(&storage), &len);
        if (n >= 0) {
            src = Endpoint::from_sockaddr(
                reinterpret_cast<const sockaddr*>(&storage), len);
        }
        return n;
    }

   private:
    static constexpr int invalid_fd = -1;

    int fd_ = invalid_fd;
    RecvCallback recv_cb_;

    void open_and_bind(uint16_t port) {
        try {
            open_and_bind_ipv6(port);
            return;
        } catch (...) {
            close_if_open();
        }

        open_and_bind_ipv4(port);
    }

    void open_and_bind_endpoint(const Endpoint& endpoint) {
        if (endpoint.family() == AF_INET6) {
            fd_ = ::socket(AF_INET6, SOCK_DGRAM, 0);
            if (fd_ < 0) {
                throw_system_error("socket");
            }
            try {
                set_reuse_addr();
                set_dual_stack();
                bind_endpoint(endpoint);
                set_non_blocking();
            } catch (...) {
                close_if_open();
                throw;
            }
            return;
        }

        if (endpoint.family() == AF_INET) {
            fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (fd_ < 0) {
                throw_system_error("socket");
            }
            try {
                set_reuse_addr();
                bind_endpoint(endpoint);
                set_non_blocking();
            } catch (...) {
                close_if_open();
                throw;
            }
            return;
        }

        errno = EINVAL;
        throw_system_error("bind(endpoint)");
    }

    void open_and_bind_ipv6(uint16_t port) {
        fd_ = ::socket(AF_INET6, SOCK_DGRAM, 0);
        if (fd_ < 0) {
            throw_system_error("socket");
        }

        try {
            set_reuse_addr();
            set_dual_stack();
            bind_any(port);
            set_non_blocking();
        } catch (...) {
            close_if_open();
            throw;
        }
    }

    void open_and_bind_ipv4(uint16_t port) {
        fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd_ < 0) {
            throw_system_error("socket");
        }

        try {
            set_reuse_addr();
            bind_any_ipv4(port);
            set_non_blocking();
        } catch (...) {
            close_if_open();
            throw;
        }
    }

    void set_reuse_addr() {
        int on = 1;
        if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            throw_system_error("setsockopt(SO_REUSEADDR)");
        }
    }

    void set_dual_stack() {
        int off = 0;
        if (::setsockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) <
            0) {
            throw_system_error("setsockopt(IPV6_V6ONLY)");
        }
    }

    void bind_any(uint16_t port) {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        addr.sin6_addr = in6addr_any;

        if (::bind(fd_, reinterpret_cast<const sockaddr*>(&addr),
                   sizeof(addr)) < 0) {
            throw_system_error("bind");
        }
    }

    void bind_any_ipv4(uint16_t port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (::bind(fd_, reinterpret_cast<const sockaddr*>(&addr),
                   sizeof(addr)) < 0) {
            throw_system_error("bind");
        }
    }

    void bind_endpoint(const Endpoint& endpoint) {
        if (::bind(fd_, endpoint.addr(), endpoint.size()) < 0) {
            throw_system_error("bind");
        }
    }

    void set_non_blocking() {
        const int flags = ::fcntl(fd_, F_GETFL, 0);
        if (flags < 0) {
            throw_system_error("fcntl(F_GETFL)");
        }
        if (::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            throw_system_error("fcntl(F_SETFL)");
        }
    }

    void close_if_open() {
        if (is_open()) {
            ::close(fd_);
            fd_ = invalid_fd;
        }
    }

    [[noreturn]] static void throw_system_error(const char* op) {
        throw std::runtime_error(std::string(op) +
                                 " failed: " + std::strerror(errno));
    }
};

}  // namespace wg

#endif  // SOCKET_C_HPP
