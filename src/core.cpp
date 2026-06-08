#include "core.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>

#include "crypto.hpp"

namespace wg {
namespace {

// 后台循环的最大睡眠时间。TimerManager 可能要求更早醒来。
constexpr auto kDefaultPollSleep = std::chrono::milliseconds(10);

}  // namespace

Core::Core() = default;

Core::~Core() { stop(); }

// ============================================================================
// Lifecycle
// ============================================================================

bool Core::initialize(const PrivateKey& local_private,
                      const PublicKey& local_public) {
    // Core 初始化的顺序很重要：
    // 1. 初始化 crypto/provider。
    // 2. 初始化 NoiseProtocol 的本地身份和预计算 hash。
    // 3. 用本地公钥构造 sender/receiver。
    // 4. 注册默认计时器。start() 之后后台循环会持续 poll 它们。
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
    if (!protocol_.initialized() || local_endpoint.port() == 0 ||
        local_endpoint.size() == 0) {
        return false;
    }

    try {
        socket_ = std::make_unique<UdpSocket>(local_endpoint);
        return true;
    } catch (const std::runtime_error&) {
        socket_.reset();
        return false;
    }
}

bool Core::start() {
    // start() 只负责启动事件循环。没有 socket 或协议未初始化时，不创建半工作
    // 状态，直接失败。
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

// ============================================================================
// Peer Registry
// ============================================================================

Peer* Core::add_peer(const PublicKey& remote_static, const Endpoint& endpoint,
                     const PreSharedKey& psk) {
    // Peer 构造时只知道对端身份；依赖本地私钥的预计算材料要在这里补齐。
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

// ============================================================================
// Sending and Handshake Entry Points
// ============================================================================

SendResult Core::send_to_peer(Peer& peer, std::span<const uint8_t> packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!socket_ || !sender_) {
        return {};
    }

    // Core 不缓存业务明文。没有可用会话时，先发 initiation，调用方在握手
    // 完成后再次调用 send_to_peer()。
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

    // CookieReply 只保存 cookie，不自动重发。调用方显式 retry 时，Core 根据
    // pending keypair 的角色选择重发哪种握手包。
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

bool Core::has_valid_session(Peer& peer) const {
    std::lock_guard<std::mutex> lock(mutex_);
    Keypair* current = peer.keypairs().current().get();
    return current != nullptr && current->is_valid();
}

bool Core::has_valid_session(const PublicKey& remote_static) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const Peer* peer = peer_manager_.find_by_public_key(remote_static);
    if (peer == nullptr) {
        return false;
    }
    Keypair* current = peer->keypairs().current().get();
    return current != nullptr && current->is_valid();
}

// ============================================================================
// Receive Pump
// ============================================================================

ReceiveResult Core::poll_once() {
    // Timer 回调允许调用 Core 的发送接口，因此不能在持有 Core mutex 时执行。
    tick();

    std::lock_guard<std::mutex> lock(mutex_);
    if (!socket_ || !receiver_) {
        return {};
    }

    // 单次读取一个 UDP datagram。后台循环会反复调用本函数；需要高吞吐时可以
    // 在这里改成 drain-until-EAGAIN 的批处理模型。
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

// ============================================================================
// Timers and Options
// ============================================================================

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

// ============================================================================
// Callbacks and Diagnostics
// ============================================================================

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

// ============================================================================
// Internal Keypair / Index Management
// ============================================================================

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
    // KeypairManager 只拥有 current/previous/next 三槽；IndexTable 只保存非拥有
    // 指针用于收包定位。每次挤掉旧 next 时必须同步移除旧 index。
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
    // 发起方每次 initiation 都安装一个新的 next keypair。若发送失败，移除
    // index_table_ 中刚注册的映射，避免留下不可达的 receiver index。
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
    // responder 收到 CookieReply 后复用原 responder keypair 重发 response。
    // 这里不重新安装 keypair，否则 sender/receiver index 会变，initiator
    // 收到 response 时就找不到原先等待中的 keypair。
    if (!sender_ || !socket_) {
        return {};
    }
    return sender_->send_response(*socket_, protocol_, peer, keypair);
}

// ============================================================================
// Receive Result Orchestration
// ============================================================================

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
            // responder 路径：已验证并消费 initiation，创建 responder keypair，
            // 立即回 response。若对端也要求 mac2，它会回 CookieReply；本端只保存
            // cookie，等待上层调用 retry_handshake()。
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
            // initiator 路径：response 认证通过，next keypair 正式升为 current。
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
            // 只保存 cookie，不自动重发。自动重发会让上层难以控制握手节奏，
            // 也不利于测试双端 cookie challenge 的中间状态。
            if (logger_) {
                logger_->debug(
                    "cookie reply consumed; waiting for manual retry");
            }
            return;
        }
        case ReceiveAction::ConsumedTransport: {
            // responder 的 keypair 在收到第一条 transport 后才激活并轮转到
            // current。这与 WireGuard 的“响应方首包确认”语义一致。
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

// ============================================================================
// Background Loop
// ============================================================================

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
