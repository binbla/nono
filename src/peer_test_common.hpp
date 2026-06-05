#pragma once

#include <poll.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <span>
#include <string>
#include <string_view>

#include "crypto.hpp"
#include "endpoint.hpp"
#include "index_table.hpp"
#include "messages.hpp"
#include "noise.hpp"
#include "peer_manager.hpp"
#include "protocol.hpp"
#include "receive.hpp"
#include "send.hpp"
#include "socket_c.hpp"
#include "tai64n.hpp"
#include "types.hpp"

namespace wg::peer_test {

inline std::string to_hex(std::span<const uint8_t> bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return out.str();
}

template <size_t N>
std::string to_hex(const std::array<uint8_t, N>& bytes) {
    return to_hex(std::span<const uint8_t>(bytes.data(), bytes.size()));
}

inline bool parse_public_key(std::string_view text, PublicKey& out) {
    std::string compact;
    compact.reserve(text.size());
    for (char c : text) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            compact.push_back(c);
        }
    }
    if (compact.size() != out.size() * 2) {
        return false;
    }

    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int value = 0;
        const char* begin = compact.data() + i * 2;
        const char* end = begin + 2;
        auto [ptr, ec] = std::from_chars(begin, end, value, 16);
        if (ec != std::errc{} || ptr != end) {
            return false;
        }
        out[i] = static_cast<uint8_t>(value);
    }
    return true;
}

inline std::string printable(std::span<const uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (uint8_t byte : bytes) {
        out.push_back(std::isprint(byte) ? static_cast<char>(byte) : '.');
    }
    return out;
}

inline const char* action_name(ReceiveAction action) {
    switch (action) {
        case ReceiveAction::Drop:
            return "Drop";
        case ReceiveAction::ConsumedCookieReply:
            return "ConsumedCookieReply";
        case ReceiveAction::ConsumedInitiation:
            return "ConsumedInitiation";
        case ReceiveAction::ConsumedResponse:
            return "ConsumedResponse";
        case ReceiveAction::ConsumedTransport:
            return "ConsumedTransport";
        case ReceiveAction::SentCookieReply:
            return "SentCookieReply";
    }
    return "Unknown";
}

inline const char* error_name(ReceiveError error) {
    switch (error) {
        case ReceiveError::None:
            return "None";
        case ReceiveError::ShortPacket:
            return "ShortPacket";
        case ReceiveError::UnknownMessageType:
            return "UnknownMessageType";
        case ReceiveError::InvalidReserved:
            return "InvalidReserved";
        case ReceiveError::InvalidMac1:
            return "InvalidMac1";
        case ReceiveError::InvalidMac2:
            return "InvalidMac2";
        case ReceiveError::UnknownPeer:
            return "UnknownPeer";
        case ReceiveError::UnknownIndex:
            return "UnknownIndex";
        case ReceiveError::CryptoFailed:
            return "CryptoFailed";
        case ReceiveError::Replay:
            return "Replay";
        case ReceiveError::OutputTooSmall:
            return "OutputTooSmall";
        case ReceiveError::SocketFailed:
            return "SocketFailed";
    }
    return "Unknown";
}

class PeerTest {
   public:
    explicit PeerTest(uint16_t default_port) : default_port_(default_port) {}

    int run(int argc, char** argv) {
        uint16_t port = default_port_;
        if (argc > 1) {
            int parsed = std::stoi(argv[1]);
            if (parsed <= 0 || parsed > 65535) {
                std::cerr << "invalid port\n";
                return 1;
            }
            port = static_cast<uint16_t>(parsed);
        }

        if (!crypto::init()) {
            std::cerr << "crypto init failed\n";
            return 1;
        }
        if (!protocol_.generate_identity(local_private_, local_public_) ||
            !protocol_.initialize(local_private_, local_public_)) {
            std::cerr << "protocol init failed\n";
            return 1;
        }

        try {
            socket_ = std::make_unique<UdpSocket>(port);
        } catch (const std::exception& e) {
            std::cerr << "bind failed: " << e.what() << "\n";
            return 1;
        }

        sender_ = std::make_unique<Sender>(local_public_);
        receiver_ = std::make_unique<Receiver>(local_public_);
        sender_->set_packet_logger([this](std::span<const uint8_t> packet) {
            log_packet("TX", packet);
        });

        std::cout << "listening on 127.0.0.1:" << socket_->local_port()
                  << "\n";
        std::cout << "local public key:\n" << to_hex(local_public_) << "\n";

        if (!read_remote_peer()) {
            return 1;
        }

        std::cout << "commands: handshake | send <text> | state | quit\n";
        prompt();

        while (running_) {
            pollfd fds[2]{};
            fds[0].fd = socket_->fd();
            fds[0].events = POLLIN;
            fds[1].fd = STDIN_FILENO;
            fds[1].events = POLLIN;

            const int rc = ::poll(fds, 2, 500);
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "poll failed: " << std::strerror(errno) << "\n";
                return 1;
            }

            if (fds[0].revents & POLLIN) {
                read_socket();
                prompt();
            }
            if (fds[1].revents & POLLIN) {
                std::string line;
                if (!std::getline(std::cin, line)) {
                    break;
                }
                handle_command(line);
                if (running_) {
                    prompt();
                }
            }
        }

        return 0;
    }

   private:
    uint16_t default_port_ = 0;
    bool running_ = true;
    PrivateKey local_private_{};
    PublicKey local_public_{};
    NoiseProtocol protocol_;
    PeerManager peers_;
    IndexTable index_table_;
    std::unique_ptr<UdpSocket> socket_;
    std::unique_ptr<Sender> sender_;
    std::unique_ptr<Receiver> receiver_;
    Peer* peer_ = nullptr;

    bool read_remote_peer() {
        PublicKey remote_public{};
        std::string line;

        while (true) {
            std::cout << "remote public key hex: " << std::flush;
            if (!std::getline(std::cin, line)) {
                return false;
            }
            if (parse_public_key(line, remote_public)) {
                break;
            }
            std::cout << "need 64 hex chars\n";
        }

        uint16_t remote_port = 0;
        while (true) {
            std::cout << "remote port: " << std::flush;
            if (!std::getline(std::cin, line)) {
                return false;
            }
            int parsed = 0;
            auto [ptr, ec] =
                std::from_chars(line.data(), line.data() + line.size(), parsed);
            if (ec == std::errc{} && ptr == line.data() + line.size() &&
                parsed > 0 && parsed <= 65535) {
                remote_port = static_cast<uint16_t>(parsed);
                break;
            }
            std::cout << "invalid port\n";
        }

        PeerConfig config;
        config.remote_static = remote_public;
        config.endpoint = Endpoint::from_ipv4("127.0.0.1", remote_port);
        peer_ = &peers_.add_peer(config);
        if (!peer_->initialize(local_private_, protocol_.base_hash())) {
            std::cerr << "peer init failed\n";
            return false;
        }

        std::cout << "remote peer ready: 127.0.0.1:" << remote_port << "\n";
        return true;
    }

    KeypairIndex next_index() {
        KeypairIndex index = 0;
        do {
            crypto::random_bytes(
                std::span<uint8_t>(reinterpret_cast<uint8_t*>(&index),
                                   sizeof(index)));
        } while (index == 0 || index_table_.contains(index));
        return index;
    }

    std::shared_ptr<Keypair> create_keypair(Peer& peer, bool initiator) {
        auto keypair = std::make_shared<Keypair>();
        keypair->local_index = next_index();
        keypair->owner = &peer;
        keypair->created_at = Timestamp::now();
        keypair->last_used_at = keypair->created_at;
        keypair->i_am_the_initiator = initiator;
        index_table_.set(keypair->local_index, keypair.get());
        return keypair;
    }

    void activate_keypair(Peer& peer, std::shared_ptr<Keypair> keypair,
                          bool initiator) {
        keypair->created_at = Timestamp::now();
        keypair->last_used_at = keypair->created_at;

        peer.keypairs().install_new(keypair);
        peer.keypairs().rotate();

        std::cout << "keypair active: role="
                  << (initiator ? "initiator" : "responder")
                  << " local_index=" << keypair->local_index
                  << " remote_index=" << keypair->remote_index << "\n";
    }

    void start_handshake() {
        if (peer_ == nullptr) {
            std::cout << "no peer\n";
            return;
        }

        auto keypair = create_keypair(*peer_, true);
        peer_->keypairs().install_new(keypair);

        SendResult result =
            sender_->send_initiation(*socket_, protocol_, *peer_, *keypair);
        std::cout << "handshake initiation: ok=" << result.ok
                  << " bytes=" << result.bytes_sent
                  << " local_index=" << keypair->local_index << "\n";
    }

    void send_text(std::string_view text) {
        if (peer_ == nullptr) {
            std::cout << "no peer\n";
            return;
        }

        std::span<const uint8_t> plaintext(
            reinterpret_cast<const uint8_t*>(text.data()), text.size());
        SendResult result =
            sender_->send_transport(*socket_, protocol_, *peer_, plaintext);
        std::cout << "send: ok=" << result.ok
                  << " bytes=" << result.bytes_sent
                  << " text=\"" << text << "\"\n";
    }

    void read_socket() {
        std::array<uint8_t, UdpSocket::recv_buffer_size> buffer{};
        while (true) {
            Endpoint src;
            const ssize_t n = socket_->recv_once(buffer, src);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == EINTR) {
                    return;
                }
                std::cerr << "recv failed: " << std::strerror(errno) << "\n";
                return;
            }
            if (n == 0) {
                continue;
            }

            std::span<const uint8_t> packet(buffer.data(),
                                            static_cast<size_t>(n));
            log_packet("RX", packet);

            std::array<uint8_t, PAYLOAD_MAX_SIZE> plaintext{};
            ReceiveResult result = receiver_->handle_packet(
                *socket_, protocol_, peers_, index_table_, packet, src,
                std::span<uint8_t>(plaintext.data(), plaintext.size()));

            std::cout << "receive: action=" << action_name(result.action)
                      << " error=" << error_name(result.error) << "\n";

            if (result.action == ReceiveAction::ConsumedInitiation &&
                result.peer != nullptr) {
                reply_to_handshake(*result.peer);
            } else if (result.action == ReceiveAction::ConsumedResponse &&
                       result.peer != nullptr) {
                finish_initiator_handshake(*result.peer);
            } else if (result.action == ReceiveAction::ConsumedTransport) {
                std::span<const uint8_t> plain(plaintext.data(),
                                               result.plaintext_size);
                std::cout << "plaintext hex=" << to_hex(plain) << "\n";
                std::cout << "plaintext text=\"" << printable(plain)
                          << "\"\n";
            }
        }
    }

    void reply_to_handshake(Peer& peer) {
        auto keypair = create_keypair(peer, false);
        keypair->remote_index = peer.handshake().remote_index;

        SendResult result =
            sender_->send_response(*socket_, protocol_, peer, *keypair);
        std::cout << "handshake response: ok=" << result.ok
                  << " bytes=" << result.bytes_sent
                  << " local_index=" << keypair->local_index << "\n";
        if (result.ok) {
            activate_keypair(peer, keypair, false);
        }
    }

    void finish_initiator_handshake(Peer& peer) {
        auto pending = peer.keypairs().next();
        if (!pending) {
            std::cout << "no pending initiator keypair\n";
            return;
        }
        activate_keypair(peer, pending, true);
    }

    void handle_command(const std::string& line) {
        if (line == "quit" || line == "exit") {
            running_ = false;
            return;
        }
        if (line == "handshake") {
            start_handshake();
            return;
        }
        if (line == "state") {
            print_state();
            return;
        }
        if (line.rfind("send ", 0) == 0) {
            send_text(std::string_view(line).substr(5));
            return;
        }
        if (!line.empty()) {
            std::cout << "unknown command\n";
        }
    }

    void print_state() const {
        std::cout << "local_port=" << socket_->local_port()
                  << " public=" << to_hex(local_public_) << "\n";
        if (peer_ == nullptr) {
            std::cout << "peer=none\n";
            return;
        }
        std::cout << "peer_public=" << to_hex(peer_->remote_static()) << "\n";
        if (peer_->endpoint()) {
            std::cout << "peer_port=" << peer_->endpoint()->port() << "\n";
        }
        std::cout << "handshake_state="
                  << static_cast<int>(peer_->handshake().state)
                  << " hs.local=" << peer_->handshake().local_index
                  << " hs.remote=" << peer_->handshake().remote_index << "\n";

        auto current = peer_->keypairs().current();
        auto next = peer_->keypairs().next();
        std::cout << "current="
                  << (current ? std::to_string(current->local_index) : "none")
                  << " sendable="
                  << (current && current->is_sendable() ? "yes" : "no")
                  << " next="
                  << (next ? std::to_string(next->local_index) : "none")
                  << "\n";
    }

    void log_packet(const char* direction,
                    std::span<const uint8_t> packet) const {
        std::cout << "\n[" << direction << "] bytes=" << packet.size() << "\n";
        std::cout << "[" << direction << "] hex=" << to_hex(packet) << "\n";
        std::cout << "[" << direction << "] text=\"" << printable(packet)
                  << "\"\n";
    }

    void prompt() const { std::cout << "> " << std::flush; }
};

inline int run_peer_test(uint16_t default_port, int argc, char** argv) {
    PeerTest app(default_port);
    return app.run(argc, argv);
}

}  // namespace wg::peer_test
