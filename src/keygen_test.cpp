#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>

#include "crypto.hpp"

namespace {

void print_hex(std::span<const uint8_t> bytes) {
    std::ios old_state(nullptr);
    old_state.copyfmt(std::cout);

    for (uint8_t byte : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(byte);
    }

    std::cout.copyfmt(old_state);
}

}  // namespace

int main() {
    if (!wg::crypto::init()) {
        std::cerr << "crypto init failed\n";
        return 1;
    }

    wg::PrivateKey private_key{};
    wg::PublicKey public_key{};
    if (!wg::crypto::generate_static_keypair(private_key, public_key)) {
        std::cerr << "keypair generation failed\n";
        return 1;
    }

    std::cout << "private_key: ";
    print_hex(private_key);
    std::cout << "\n";

    std::cout << "public_key:  ";
    print_hex(public_key);
    std::cout << "\n";
    return 0;
}
