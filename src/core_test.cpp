#include <array>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>

#include "core.hpp"
#include "endpoint.hpp"
#include "logger.hpp"
#include "types.hpp"

namespace {

std::string to_hex(std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0f]);
    }
    return out;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (c >= 'a' && c <= 'f') {
        return 10 + c - 'a';
    }
    return -1;
}

bool parse_hex_key(const std::string& hex, wg::PublicKey& out) {
    if (hex.size() != out.size() * 2) {
        return false;
    }
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = hex_value(hex[i * 2]);
        const int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

void print_menu() {
    std::cout << "\n"
              << "1. normal handshake\n"
              << "2. toggle cookie reply requirement for incoming handshakes\n"
              << "3. send message\n"
              << "4. show my public key\n"
              << "5. retry last handshake packet\n"
              << "q. quit\n"
              << "> " << std::flush;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <local-port>\n"
                  << "example terminals:\n"
                  << "  " << argv[0] << " 40001\n"
                  << "  " << argv[0] << " 40002\n";
        return 1;
    }

    const auto port = static_cast<uint16_t>(std::stoi(argv[1]));
    wg::Core core;
    if (!core.generate_identity_and_initialize()) {
        std::cerr << "failed to initialize identity\n";
        return 1;
    }
    if (!core.bind(wg::Endpoint::from_ipv4("0.0.0.0", port))) {
        std::cerr << "failed to bind port " << port << "\n";
        return 1;
    }

    std::cout << "local port: " << port << "\n";
    std::cout << "my public key(hex): " << to_hex(core.local_public()) << "\n";

    std::cout << "peer public key(hex): " << std::flush;
    std::string peer_hex;
    std::getline(std::cin, peer_hex);
    wg::PublicKey peer_key{};
    if (!parse_hex_key(peer_hex, peer_key)) {
        std::cerr << "invalid peer public key\n";
        return 1;
    }

    const uint16_t peer_port = port == 40001 ? 40002 : 40001;
    wg::Endpoint peer_endpoint = wg::Endpoint::from_ipv4("127.0.0.1", peer_port);
    wg::Peer* peer = core.add_peer(peer_key, peer_endpoint);
    if (peer == nullptr) {
        std::cerr << "failed to add peer\n";
        return 1;
    }

    wg::Logger& logger = wg::Logger::default_logger();
    core.set_packet_callback([](wg::Peer&, std::span<const uint8_t> packet) {
        std::string text(packet.begin(), packet.end());
        wg::Logger::default_logger().info("APP RX plaintext=\"" + text + "\"");
        std::cout << "> " << std::flush;
    });
    logger.info("logger ready");

    if (!core.start()) {
        std::cerr << "failed to start core\n";
        return 1;
    }

    bool require_cookie = false;
    for (;;) {
        print_menu();
        std::string choice;
        if (!std::getline(std::cin, choice)) {
            break;
        }

        if (choice == "q" || choice == "Q") {
            break;
        }
        if (choice == "1") {
            wg::SendResult r = core.begin_handshake(*peer);
            std::cout << (r.ok ? "handshake initiation sent\n"
                               : "handshake initiation failed\n");
        } else if (choice == "2") {
            require_cookie = !require_cookie;
            core.set_force_cookie_reply(require_cookie);
            std::cout << "incoming cookie reply requirement: "
                      << (require_cookie ? "on" : "off") << "\n";
            std::cout << "To test cookie handshake, turn this on here, then run "
                         "option 1 on the other instance.\n";
        } else if (choice == "3") {
            std::cout << "message: " << std::flush;
            std::string message;
            std::getline(std::cin, message);
            wg::SendResult r =
                core.send_to_peer(*peer, std::span<const uint8_t>(
                                             reinterpret_cast<const uint8_t*>(
                                                 message.data()),
                                             message.size()));
            std::cout << (r.ok ? "message sent\n"
                               : "no active session; handshake started or send "
                                 "failed, retry after handshake\n");
        } else if (choice == "4") {
            std::cout << "my public key(hex): " << to_hex(core.local_public())
                      << "\n";
        } else if (choice == "5") {
            wg::SendResult r = core.retry_handshake(*peer);
            std::cout << (r.ok ? "handshake retry sent\n"
                               : "handshake retry failed\n");
        }
    }

    core.stop();
    return 0;
}
