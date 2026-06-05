#include "core.hpp"

#include <chrono>

#include "crypto.hpp"

namespace wg {

Core::Core() = default;

Core::~Core() { stop(); }

bool Core::initialize(const PrivateKey& local_private,
                      const PublicKey& local_public) {
    if (!crypto::init()) {
        return false;
    }
    if (!protocol_.initialize(local_private, local_public)) {
        return false;
    }

    register_default_timers();
    return true;
}

bool Core::generate_identity_and_initialize() {
    PrivateKey private_key{};
    PublicKey public_key{};
    if (!protocol_.generate_identity(private_key, public_key)) {
        return false;
    }
    return initialize(private_key, public_key);
}

bool Core::bind(const Endpoint& local_endpoint) {
    (void)local_endpoint;
    return false;
}

bool Core::start() {
    running_ = true;
    return true;
}

void Core::stop() { running_ = false; }

bool Core::running() const { return running_; }

Peer* Core::add_peer(const PublicKey& remote_static, const Endpoint& endpoint,
                     const PreSharedKey& psk) {
    PeerConfig config{
        .remote_static = remote_static,
        .preshared_key = psk,
        .endpoint = endpoint,
    };
    Peer& peer = peer_manager_.add_peer(config);
    if (protocol_.initialized() &&
        !peer.initialize_crypto_state(protocol_.local_private(),
                                      protocol_.base_hash())) {
        peer_manager_.remove_peer(remote_static);
        return nullptr;
    }
    return &peer;
}

bool Core::remove_peer(const PublicKey& remote_static) {
    return peer_manager_.remove_peer(remote_static);
}

Peer* Core::find_peer(const PublicKey& remote_static) {
    return peer_manager_.find_by_public_key(remote_static);
}

Peer* Core::find_peer_by_endpoint(const Endpoint& endpoint) {
    return peer_manager_.find_by_endpoint(endpoint);
}

SendResult Core::send_to_peer(Peer& peer, std::span<const uint8_t> packet) {
    (void)peer;
    (void)packet;
    return {};
}

SendResult Core::send_to_peer(const PublicKey& remote_static,
                              std::span<const uint8_t> packet) {
    Peer* peer = find_peer(remote_static);
    if (peer == nullptr) {
        return {};
    }
    return send_to_peer(*peer, packet);
}

ReceiveResult Core::poll_once() { return {}; }

void Core::tick() { timers_.poll(); }

void Core::register_default_timers() {
    timers_.clear();
    timers_.schedule_every(std::chrono::minutes(2),
                           [this] { protocol_.rotate_secret_for_cookie(); },
                           "protocol.cookie_secret.rotate");
}

TimerManager& Core::timers() { return timers_; }

PeerManager& Core::peer_manager() { return peer_manager_; }

IndexTable& Core::index_table() { return index_table_; }

NoiseProtocol& Core::protocol() { return protocol_; }

}  // namespace wg
