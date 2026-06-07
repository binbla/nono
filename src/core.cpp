#include "core.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>

#include "crypto.hpp"

namespace wg {
namespace {
constexpr auto kDefaultPollSleep = std::chrono::milliseconds(10);
}

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

    sender_ = std::make_unique<Sender>(protocol_.local_public());
    ReceiveConfig receive_config;
    receive_config.load_monitor = &load_monitor_;
    receiver_ = std::make_unique<Receiver>(protocol_.local_public(),
                                           receive_config);

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
    if (!protocol_.initialized() || local_endpoint.port() == 0) {
        return false;
    }

    try {
        socket_ = std::make_unique<UdpSocket>(local_endpoint.port());
        return true;
    } catch (const std::runtime_error&) {
        socket_.reset();
        return false;
    }
}

bool Core::start() {
    if (running_.load(std::memory_order_acquire)) {
        return true;
    }
    if (!socket_ || !sender_ || !receiver_) {
        return false;
    }
    running_.store(true, std::memory_order_release);
    worker_ = std::thread(&Core::run_loop, this);
    return true;
}

void Core::stop() {
    running_.store(false, std::memory_order_release);
    if (worker_.joinable()) {
        worker_.join();
    }
}

bool Core::running() const { return running_.load(std::memory_order_acquire); }

const PublicKey& Core::local_public() const { return protocol_.local_public(); }

Peer* Core::add_peer(const PublicKey& remote_static, const Endpoint& endpoint,
                     const PreSharedKey& psk) {
    PeerConfig config{
        .remote_static = remote_static,
        .preshared_key = psk,
        .endpoint = endpoint,
    };
    Peer& peer = peer_manager_.add_peer(config);
    if (protocol_.initialized() &&
        !peer.initialize(protocol_.local_private(), protocol_.base_hash())) {
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
    std::lock_guard<std::mutex> lock(mutex_);
    if (!socket_ || !sender_) {
        return {};
    }

    Keypair* current = peer.keypairs().current().get();
    if (current == nullptr || !current->is_valid()) {
        return initiate_handshake(peer);
    }

    if (packet.size() > PAYLOAD_MAX_SIZE) {
        return {};
    }
    return sender_->send_transport(*socket_, protocol_, peer, packet);
}

SendResult Core::send_to_peer(const PublicKey& remote_static,
                              std::span<const uint8_t> packet) {
    Peer* peer = find_peer(remote_static);
    if (peer == nullptr) {
        return {};
    }
    return send_to_peer(*peer, packet);
}

SendResult Core::begin_handshake(Peer& peer) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!socket_ || !sender_) {
        return {};
    }
    return initiate_handshake(peer);
}

SendResult Core::begin_handshake(const PublicKey& remote_static) {
    Peer* peer = find_peer(remote_static);
    if (peer == nullptr) {
        return {};
    }
    return begin_handshake(*peer);
}

SendResult Core::retry_handshake(Peer& peer) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!socket_ || !sender_) {
        return {};
    }

    Keypair* pending = peer.keypairs().next().get();
    if (pending != nullptr && !pending->i_am_the_initiator) {
        return resend_response(peer, *pending);
    }
    return initiate_handshake(peer);
}

SendResult Core::retry_handshake(const PublicKey& remote_static) {
    Peer* peer = find_peer(remote_static);
    if (peer == nullptr) {
        return {};
    }
    return retry_handshake(*peer);
}

ReceiveResult Core::poll_once() {
    std::lock_guard<std::mutex> lock(mutex_);
    tick();
    if (!socket_ || !receiver_) {
        return {};
    }

    std::array<uint8_t, UdpSocket::recv_buffer_size> packet{};
    std::array<uint8_t, PAYLOAD_MAX_SIZE> plaintext{};
    Endpoint src;
    const ssize_t n = socket_->recv_once(packet, src);
    if (n < 0) {
        return {};
    }

    ReceiveResult result = receiver_->handle_packet(
        *socket_, protocol_, peer_manager_, index_table_,
        std::span<const uint8_t>(packet.data(), static_cast<size_t>(n)), src,
        plaintext);
    handle_receive_result(
        result, std::span<const uint8_t>(plaintext.data(),
                                         result.plaintext_size));
    return result;
}

void Core::tick() { timers_.poll(); }

void Core::register_default_timers() {
    timers_.clear();
    timers_.schedule_every(
        std::chrono::minutes(2),
        [this] { protocol_.rotate_secret_for_cookie(); },
        "protocol.cookie_secret.rotate");
}

void Core::set_force_cookie_reply(bool force) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (receiver_) {
        receiver_->set_force_mac2_validation(force);
    }
}

TimerManager& Core::timers() { return timers_; }

PeerManager& Core::peer_manager() { return peer_manager_; }

IndexTable& Core::index_table() { return index_table_; }

NoiseProtocol& Core::protocol() { return protocol_; }

void Core::set_packet_callback(PacketCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    packet_callback_ = std::move(cb);
}

void Core::set_receive_event_callback(ReceiveEventCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    receive_event_callback_ = std::move(cb);
}

void Core::set_wire_packet_callback(WirePacketCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (sender_) {
        sender_->set_packet_logger(std::move(cb));
    }
}

void Core::set_logger(Logger* logger) {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_ = logger != nullptr ? logger : &Logger::default_logger();
}

KeypairIndex Core::allocate_index() {
    std::array<uint8_t, sizeof(KeypairIndex)> bytes{};
    for (;;) {
        if (!crypto::fill_random(bytes)) {
            return 0;
        }
        KeypairIndex index = 0;
        for (size_t i = 0; i < bytes.size(); ++i) {
            index |= static_cast<KeypairIndex>(bytes[i]) << (8 * i);
        }
        if (index != 0 && !index_table_.contains(index)) {
            return index;
        }
    }
}

Keypair* Core::install_next_keypair(Peer& peer, bool i_am_the_initiator) {
    const KeypairIndex local_index = allocate_index();
    if (local_index == 0) {
        return nullptr;
    }

    auto keypair =
        std::make_shared<Keypair>(local_index, &peer, i_am_the_initiator);
    Keypair* raw = keypair.get();
    const KeypairIndex evicted = peer.keypairs().install_new(std::move(keypair));
    if (evicted != 0) {
        index_table_.erase(evicted);
    }
    index_table_.add(local_index, raw);
    return raw;
}

SendResult Core::initiate_handshake(Peer& peer) {
    Keypair* keypair = install_next_keypair(peer, true);
    if (keypair == nullptr || !sender_) {
        return {};
    }

    SendResult result =
        sender_->send_initiation(*socket_, protocol_, peer, *keypair);
    if (!result.ok) {
        index_table_.erase(keypair->local_index);
    }
    return result;
}

SendResult Core::resend_response(Peer& peer, Keypair& keypair) {
    if (!sender_ || !socket_) {
        return {};
    }
    return sender_->send_response(*socket_, protocol_, peer, keypair);
}

void Core::handle_receive_result(const ReceiveResult& result,
                                 std::span<const uint8_t> plaintext) {
    if (receive_event_callback_) {
        receive_event_callback_(result);
    }

    if (!sender_ || !socket_) {
        return;
    }

    switch (result.action) {
        case ReceiveAction::ConsumedInitiation: {
            if (result.peer == nullptr) {
                return;
            }
            Keypair* keypair = install_next_keypair(*result.peer, false);
            if (keypair == nullptr) {
                return;
            }
            SendResult sent =
                sender_->send_response(*socket_, protocol_, *result.peer,
                                       *keypair);
            if (!sent.ok) {
                index_table_.erase(keypair->local_index);
            }
            return;
        }
        case ReceiveAction::ConsumedResponse: {
            if (result.peer == nullptr) {
                return;
            }
            const KeypairIndex evicted = result.peer->keypairs().rotate();
            if (evicted != 0) {
                index_table_.erase(evicted);
            }
            return;
        }
        case ReceiveAction::ConsumedCookieReply: {
            if (logger_) {
                logger_->debug(
                    "cookie reply consumed; waiting for manual retry");
            }
            return;
        }
        case ReceiveAction::ConsumedTransport: {
            if (result.peer != nullptr && result.keypair != nullptr &&
                result.peer->keypairs().next().get() == result.keypair) {
                const KeypairIndex evicted = result.peer->keypairs().rotate();
                if (evicted != 0) {
                    index_table_.erase(evicted);
                }
            }
            if (packet_callback_ && result.peer != nullptr) {
                packet_callback_(*result.peer, plaintext);
            }
            return;
        }
        default:
            return;
    }
}

void Core::run_loop() {
    while (running_.load(std::memory_order_acquire)) {
        poll_once();
        std::this_thread::sleep_for(
            timers_.time_until_next(kDefaultPollSleep) < kDefaultPollSleep
                ? timers_.time_until_next(kDefaultPollSleep)
                : kDefaultPollSleep);
    }
}

}  // namespace wg
