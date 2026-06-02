#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

constexpr int PORT = 8888;
constexpr int MAX_EVENTS = 64;
constexpr int BUFFER_SIZE = 1024;

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

int main() {
    // 1. 创建监听 socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "socket failed\n";
        return 1;
    }

    // 允许端口复用
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind failed\n";
        return 1;
    }

    if (listen(listen_fd, SOMAXCONN) < 0) {
        std::cerr << "listen failed\n";
        return 1;
    }

    set_nonblocking(listen_fd);

    // 2. 创建 epoll
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        std::cerr << "epoll_create1 failed\n";
        return 1;
    }

    // 3. 注册 listen fd
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        std::cerr << "epoll_ctl failed\n";
        return 1;
    }

    epoll_event events[MAX_EVENTS];

    std::cout << "server listening on port " << PORT << "\n";

    // 4. 事件循环
    while (true) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            std::cerr << "epoll_wait failed\n";
            break;
        }

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;

            // 5. 新连接
            if (fd == listen_fd) {
                while (true) {
                    sockaddr_in client_addr{};
                    socklen_t client_len = sizeof(client_addr);

                    int client_fd = accept(
                        listen_fd, reinterpret_cast<sockaddr*>(&client_addr),
                        &client_len);

                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }

                        std::cerr << "accept failed\n";
                        break;
                    }

                    set_nonblocking(client_fd);

                    epoll_event client_ev{};
                    client_ev.events = EPOLLIN;
                    client_ev.data.fd = client_fd;

                    epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &client_ev);

                    char ip[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));

                    std::cout << "new client: " << ip << ":"
                              << ntohs(client_addr.sin_port) << "\n";
                }
            }

            // 6. 客户端数据
            else {
                char buffer[BUFFER_SIZE];

                ssize_t len = recv(fd, buffer, sizeof(buffer), 0);

                if (len <= 0) {
                    if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        continue;
                    }

                    std::cout << "client disconnected\n";

                    close(fd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);

                    continue;
                }

                std::cout << "recv: " << std::string(buffer, buffer + len)
                          << "\n";

                // echo
                send(fd, buffer, len, 0);
            }
        }
    }

    close(listen_fd);
    close(epfd);

    return 0;
}