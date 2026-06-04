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

inline std::string hex(std::span<const uint8_t> data) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        out << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return out.str();
}

template <size_t N>
std::string hex(const std::array<uint8_t, N>& data) {
    return hex(std::span<const uint8_t>(data.data(), data.size()));
}

inline bool parse_hex_key(std::string_view text, PublicKey& out) {
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
        auto begin = compact.data() + i * 2;
        auto end = begin + 2;
        auto [ptr, ec] = std::from_chars(begin, end, value, 16);
        if (ec != std::errc{} || ptr != end) {
            return false;
        }
        out[i] = static_cast<uint8_t>(value);
    }
    return true;
}

inline std::string endpoint_string(const Endpoint& endpoint) {
    return "127.0.0.1:" + std::to_string(endpoint.port());
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

inline std::string printable(std::span<const uint8_t> data) {
    std::string out;
    out.reserve(data.size());
    for (uint8_t byte : data) {
        out.push_back(std::isprint(byte) ? static_cast<char>(byte) : '.');
    }
    return out;
}

class PeerTestApp {
   public:
    explicit PeerTestApp(uint16_t default_port) : default_port_(default_port) {}

    int run(int argc, char** argv) {
        uint16_t local_port = default_port_;
        if (argc > 1) {
            int parsed = std::stoi(argv[1]);
            if (parsed <= 0 || parsed > 65535) {
                std::cerr << "invalid local port\n";
                return 1;
            }
            local_port = static_cast<uint16_t>(parsed);
        }

        if (!crypto::init()) {
            std::cerr << "crypto init failed\n";
            return 1;
        }
        if (!protocol_.generate_identity(local_private_, local_public_) ||
            !protocol_.initialize(local_private_, local_public_)) {
            std::cerr << "identity/protocol init failed\n";
            return 1;
        }

        try {
            socket_ = std::make_unique<UdpSocket>(local_port);
        } catch (const std::exception& e) {
            std::cerr << "bind failed: " << e.what() << "\n";
            return 1;
        }

        sender_ = std::make_unique<Sender>(local_public_);
        receiver_ = std::make_unique<Receiver>(local_public_);
        sender_->set_packet_logger([this](std::span<const uint8_t> data) {
            log_packet("TX", data, peer_ && peer_->endpoint()
                                ? endpoint_string(*peer_->endpoint())
                                : "unknown");
        });

        std::cout << "listening: 127.0.0.1:" << socket_->local_port() << "\n";
        std::cout << "local peer public key:\n" << hex(local_public_) << "\n";

        if (!read_peer_config()) {
            return 1;
        }

        std::cout << "commands: handshake | set cookie require [on|off] | state | send <text> | quit\n";
        prompt();

        while (running_) {
            pollfd fds[2]{};
            fds[0].fd = socket_->fd();
            fds[0].events = POLLIN;
            fds[1].fd = STDIN_FILENO;
            fds[1].events = POLLIN;

            int rc = ::poll(fds, 2, 500);
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "poll failed: " << std::strerror(errno) << "\n";
                return 1;
            }
            if (fds[0].revents & POLLIN) {
                receive_all();
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

    void prompt() {
        std::cout << "> " << std::flush;
    }

    bool read_peer_config() {
        std::string line;
        PublicKey remote_public{};
        while (true) {
            std::cout << "remote peer public key hex: " << std::flush;
            if (!std::getline(std::cin, line)) {
                return false;
            }
            if (parse_hex_key(line, remote_public)) {
                break;
            }
            std::cout << "invalid key: need 64 hex chars\n";
        }

        uint16_t remote_port = 0;
        while (true) {
            std::cout << "remote peer port: " << std::flush;
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
        if (!peer_->initialize_crypto_state(local_private_,
                                            protocol_.base_hash())) {
            std::cerr << "peer crypto precompute failed\n";
            return false;
        }

        std::cout << "peer ready: " << endpoint_string(*peer_->endpoint())
                  << "\n";
        return true;
    }

    KeypairIndex make_index() {
        KeypairIndex index = 0;
        do {
            crypto::random_bytes(
                std::span<uint8_t>(reinterpret_cast<uint8_t*>(&index),
                                   sizeof(index)));
        } while (index == 0 || index_table_.contains(index));
        return index;
    }

    std::shared_ptr<Keypair> make_keypair(Peer& peer, bool initiator) {
        auto keypair = std::make_shared<Keypair>();
        keypair->local_index = make_index();
        keypair->owner = &peer;
        keypair->created_at = Timestamp::now();
        keypair->last_used_at = keypair->created_at;
        keypair->i_am_the_initiator = initiator;
        index_table_.set(keypair->local_index, keypair.get());
        return keypair;
    }

    void activate_keypair(Peer& peer, std::shared_ptr<Keypair> keypair,
                          bool initiator) {
        ChainingKey ck = peer.handshake().chaining_key;
        SymmetricKey key1{};
        SymmetricKey key2{};
        noise::derive_transport_keys(ck, key1, key2);
        if (initiator) {
            keypair->set_sending(key1);
            keypair->set_receiving(key2);
        } else {
            keypair->set_sending(key2);
            keypair->set_receiving(key1);
        }
        keypair->remote_index = peer.handshake().remote_index;
        keypair->created_at = Timestamp::now();
        peer.keypairs().install_new(keypair);
        peer.keypairs().rotate();
        std::cout << "keypair activated local=" << keypair->local_index
                  << " remote=" << keypair->remote_index
                  << " role=" << (initiator ? "initiator" : "responder")
                  << "\n";
        crypto::secure_zero(ck);
        crypto::secure_zero(key1);
        crypto::secure_zero(key2);
    }

    std::shared_ptr<Keypair> pending_or_new_initiator() {
        auto pending = peer_->keypairs().next();
        if (pending && peer_->handshake().state == HandshakeState::CreatedInitiation) {
            return pending;
        }
        auto keypair = make_keypair(*peer_, true);
        peer_->keypairs().install_new(keypair);
        return keypair;
    }

    void start_handshake() {
        if (!peer_) {
            std::cout << "peer not configured\n";
            return;
        }
        auto keypair = pending_or_new_initiator();
        SendResult result =
            sender_->send_initiation(*socket_, protocol_, *peer_, *keypair);
        std::cout << "send initiation: ok=" << result.ok
                  << " bytes=" << result.bytes_sent
                  << " local_index=" << keypair->local_index << "\n";
    }

    void send_text(std::string_view text) {
        if (!peer_) {
            std::cout << "peer not configured\n";
            return;
        }
        std::span<const uint8_t> bytes(
            reinterpret_cast<const uint8_t*>(text.data()), text.size());
        SendResult result =
            sender_->send_transport(*socket_, protocol_, *peer_, bytes);
        std::cout << "send text: ok=" << result.ok
                  << " bytes=" << result.bytes_sent
                  << " text=\"" << text << "\"\n";
    }

    void send_cookie_reply_for(std::span<const uint8_t> packet,
                               const Endpoint& src) {
        auto type = Receiver::peek_message_type(packet);
        if (!type) {
            return;
        }

        KeypairIndex receiver_index = 0;
        Mac mac1{};
        if (*type == MessageType::HandshakeInitiation) {
            HandshakeInitiation msg{};
            if (!Receiver::parse_initiation(packet, msg)) {
                return;
            }
            receiver_index = wire::le_to_host32(msg.sender_index);
            mac1 = msg.mac1;
        } else if (*type == MessageType::HandshakeResponse) {
            HandshakeResponse msg{};
            if (!Receiver::parse_response(packet, msg)) {
                return;
            }
            receiver_index = wire::le_to_host32(msg.sender_index);
            mac1 = msg.mac1;
        } else {
            return;
        }

        SendResult result = sender_->send_cookie_reply(
            *socket_, protocol_, receiver_index, mac1, src);
        std::cout << "send cookie reply: ok=" << result.ok
                  << " bytes=" << result.bytes_sent
                  << " receiver_index=" << receiver_index << "\n";
    }

    void receive_all() {
        std::array<uint8_t, UdpSocket::recv_buffer_size> buffer{};
        while (true) {
            Endpoint src;
            ssize_t n = socket_->recv_once(buffer, src);
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
            log_packet("RX", packet, endpoint_string(src));

            std::array<uint8_t, PAYLOAD_MAX_SIZE> plaintext{};
            ReceiveResult result = receiver_->handle_packet(
                *socket_, protocol_, peers_, index_table_, packet, src,
                std::span<uint8_t>(plaintext.data(), plaintext.size()));
            std::cout << "receive result: action=" << action_name(result.action)
                      << " error=" << error_name(result.error) << "\n";

            if (result.error == ReceiveError::InvalidMac2) {
                send_cookie_reply_for(packet, src);
                continue;
            }
            if (result.action == ReceiveAction::ConsumedInitiation &&
                result.peer != nullptr) {
                auto keypair = make_keypair(*result.peer, false);
                keypair->remote_index = result.peer->handshake().remote_index;
                SendResult sent = sender_->send_response(
                    *socket_, protocol_, *result.peer, *keypair);
                std::cout << "send response: ok=" << sent.ok
                          << " bytes=" << sent.bytes_sent
                          << " local_index=" << keypair->local_index << "\n";
                if (sent.ok) {
                    activate_keypair(*result.peer, keypair, false);
                }
            } else if (result.action == ReceiveAction::ConsumedResponse &&
                       result.peer != nullptr) {
                Keypair* raw =
                    index_table_.find(result.peer->handshake().local_index);
                auto pending = result.peer->keypairs().next();
                if (raw != nullptr && pending && pending.get() == raw) {
                    activate_keypair(*result.peer, pending, true);
                } else {
                    std::cout << "response consumed, but pending keypair was not found\n";
                }
            } else if (result.action == ReceiveAction::ConsumedCookieReply) {
                std::cout << "cookie stored; run 'handshake' again to retry with mac2\n";
            } else if (result.action == ReceiveAction::ConsumedTransport) {
                std::span<const uint8_t> plain(plaintext.data(),
                                               result.plaintext_size);
                std::cout << "plaintext hex=" << hex(plain) << "\n";
                std::cout << "plaintext text=\"" << printable(plain) << "\"\n";
            }
        }
    }

    void handle_command(const std::string& line) {
        if (line == "quit" || line == "exit") {
            running_ = false;
            return;
        }
        if (line == "help") {
            std::cout << "commands: handshake | set cookie require [on|off] | state | send <text> | quit\n";
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
        if (line.rfind("set cookie require", 0) == 0) {
            bool current = receiver_->needs_mac2_validation();
            bool next = !current;
            if (line.find(" on") != std::string::npos) {
                next = true;
            } else if (line.find(" off") != std::string::npos) {
                next = false;
            }
            receiver_->set_force_mac2_validation(next);
            std::cout << "cookie require: " << (next ? "on" : "off") << "\n";
            return;
        }
        if (!line.empty()) {
            std::cout << "unknown command\n";
        }
    }

    void print_state() {
        std::cout << "local_port=" << socket_->local_port()
                  << " cookie_require="
                  << (receiver_->needs_mac2_validation() ? "on" : "off")
                  << " index_table_size=" << index_table_.size() << "\n";
        if (!peer_) {
            std::cout << "peer: none\n";
            return;
        }
        std::cout << "peer_public=" << hex(peer_->remote_static()) << "\n";
        if (peer_->endpoint()) {
            std::cout << "peer_endpoint=" << endpoint_string(*peer_->endpoint())
                      << "\n";
        }
        std::cout << "handshake_state="
                  << static_cast<int>(peer_->handshake().state)
                  << " local_index=" << peer_->handshake().local_index
                  << " remote_index=" << peer_->handshake().remote_index
                  << "\n";
        auto current = peer_->keypairs().current();
        auto next = peer_->keypairs().next();
        std::cout << "current_keypair="
                  << (current ? std::to_string(current->local_index) : "none")
                  << " sendable="
                  << (current && current->is_sendable() ? "yes" : "no")
                  << " next_keypair="
                  << (next ? std::to_string(next->local_index) : "none")
                  << "\n";
    }

    void log_packet(const char* direction, std::span<const uint8_t> packet,
                    const std::string& endpoint) {
        std::cout << "\n[" << direction << "] endpoint=" << endpoint
                  << " bytes=" << packet.size() << "\n";
        std::cout << "[" << direction << "] hex=" << hex(packet) << "\n";
        std::cout << "[" << direction << "] text=\"" << printable(packet)
                  << "\"\n";
    }
};

inline int run_peer_test(uint16_t default_port, int argc, char** argv) {
    PeerTestApp app(default_port);
    return app.run(argc, argv);
}

}  // namespace wg::peer_test
