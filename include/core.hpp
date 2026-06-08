#ifndef CORE_HPP
#define CORE_HPP
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <thread>

#include "endpoint.hpp"
#include "index_table.hpp"
#include "load_monitor.hpp"
#include "logger.hpp"
#include "peer.hpp"
#include "peer_manager.hpp"
#include "protocol.hpp"
#include "receive.hpp"
#include "send.hpp"
#include "socket_c.hpp"
#include "timer.hpp"
#include "types.hpp"
namespace wg {

// Core 是可信网络层的编排入口。
//
// 下层模块的职责分工：
// - NoiseProtocol：只处理握手/传输密钥/加解密状态机。
// - Sender/Receiver：只把协议消息封装成 UDP datagram 或从 datagram 分发。
// - Peer/KeypairManager/IndexTable：保存 peer、三槽 keypair 与 receiver index。
// - Core：把以上模块连起来，负责 socket 生命周期、事件循环、计时器、
//   keypair 安装/轮转、上层回调，以及“什么时候该发下一包”。
//
// 重要约定：
// - 收到 CookieReply 只保存 cookie，不自动重发；调用方通过 retry_handshake()
//   手动触发重发。
// - send_to_peer() 如果没有可用会话，会先发起握手并返回该握手包的发送结果；
//   它不会缓存业务明文等待握手完成。
// - start() 会启动后台循环；不调用 start() 时，也可以用 poll_once()/tick()
//   同步推进。
using PacketCallback =
    std::function<void(Peer& peer, std::span<const uint8_t> packet)>;
using ReceiveEventCallback = std::function<void(const ReceiveResult& result)>;
using WirePacketCallback = std::function<void(std::span<const uint8_t> packet)>;

enum class Availability {
    Ready,
    HandshakeStarted,
    HandshakePending,
    Failed,
};

class Core {
   public:
    Core();
    ~Core();

    Core(const Core&) = delete;
    Core& operator=(const Core&) = delete;

    // ------------------------------------------------------------
    // 初始化 / 关闭
    // ------------------------------------------------------------

    bool initialize(const PrivateKey& local_private,
                    const PublicKey& local_public);

    // 生成一组临时本地身份并初始化协议栈，适合测试程序或短生命周期节点。
    bool generate_identity_and_initialize();

    // 绑定本地 UDP 地址和端口，支持 IPv4 / IPv6 Endpoint。
    bool bind(const Endpoint& local_endpoint);

    // 启动后台循环：持续 poll UDP socket，并驱动 TimerManager。
    bool start();

    void stop();

    bool running() const;

    const PublicKey& local_public() const;

    // ------------------------------------------------------------
    // Peer 管理
    // ------------------------------------------------------------

    Peer* add_peer(const PublicKey& remote_static, const Endpoint& endpoint,
                   const PreSharedKey& psk = PreSharedKey{});

    bool remove_peer(const PublicKey& remote_static);

    Peer* find_peer(const PublicKey& remote_static);

    Peer* find_peer_by_endpoint(const Endpoint& endpoint);

    // ------------------------------------------------------------
    // 发送接口
    // ------------------------------------------------------------

    SendResult send_to_peer(Peer& peer, std::span<const uint8_t> packet);

    SendResult send_to_peer(const PublicKey& remote_static,
                            std::span<const uint8_t> packet);

    // 显式发起一轮新的 Noise initiation。
    SendResult begin_handshake(Peer& peer);

    SendResult begin_handshake(const PublicKey& remote_static);

    // 手动重发当前握手阶段的下一包。
    //
    // - 如果 peer 的 next keypair 是 initiator，重发 initiation。
    // - 如果 next keypair 是 responder，重发 response。
    // - 常见触发场景：收到 CookieReply 后，上层决定继续握手。
    SendResult retry_handshake(Peer& peer);

    SendResult retry_handshake(const PublicKey& remote_static);

    // 推进 initiator 侧握手，直到 peer 可以发送 transport data。
    // responder 侧 response 只会在收到有效 initiation 后由 receive path 被动发送。
    Availability ensure_available(Peer& peer);

    Availability ensure_available(const PublicKey& remote_static);

    // 查询当前 peer 是否已有可发送 transport data 的有效 keypair。
    bool has_valid_session(Peer& peer) const;

    bool has_valid_session(const PublicKey& remote_static) const;

    // 只发送 transport data；没有有效 keypair 时直接失败，不隐式发握手。
    SendResult send_transport(Peer& peer, std::span<const uint8_t> packet);

    SendResult send_transport(const PublicKey& remote_static,
                              std::span<const uint8_t> packet);

    // ------------------------------------------------------------
    // 接收接口
    // ------------------------------------------------------------

    // 同步推进一次接收路径。后台模式下由 run_loop() 调用。
    ReceiveResult poll_once();

    // 收到并成功解密 transport data 后回调上层明文。
    void set_packet_callback(PacketCallback cb);

    // 暴露接收事件，便于测试程序或上层状态机观察握手进度。
    void set_receive_event_callback(ReceiveEventCallback cb);

    // 调试 hook：Sender 发出 wire bytes 前调用。
    void set_wire_packet_callback(WirePacketCallback cb);

    void set_logger(Logger* logger);

    // ------------------------------------------------------------
    // 定时器 / 状态推进
    // ------------------------------------------------------------

    void tick();

    // 注册协议默认周期任务，例如 cookie secret 轮转。
    void register_default_timers();

    // 测试/压测开关：强制握手包必须携带有效 mac2。
    void set_force_cookie_reply(bool force);

    TimerManager& timers();

    // ------------------------------------------------------------
    // 资源访问，给内部模块或测试使用
    // ------------------------------------------------------------

    PeerManager& peer_manager();
    IndexTable& index_table();
    NoiseProtocol& protocol();

   private:
    // 分配一个本地 receiver index，并确保不与 index_table_ 冲突。
    KeypairIndex allocate_index();

    // 创建 keypair，安装到 peer.next，并注册到 index_table_。
    Keypair* install_next_keypair(Peer& peer, bool i_am_the_initiator);

    // 发送握手包的内部入口。外层 API 负责加锁和参数检查。
    SendResult initiate_handshake(Peer& peer);
    SendResult resend_initiation(Peer& peer, Keypair& keypair);
    SendResult resend_response(Peer& peer, Keypair& keypair);

    // Receiver 只返回“发生了什么”，Core 在这里完成后续编排：
    // - 收到 initiation 后创建 responder keypair 并发送 response。
    // - 收到 response 后轮转 keypair。
    // - 收到 transport 后交给上层回调。
    void handle_receive_result(const ReceiveResult& result,
                               std::span<const uint8_t> plaintext);
    void run_loop();

    // 状态对象的拥有关系都集中在 Core：下层模块只拿引用/指针使用。
    PeerManager peer_manager_;
    IndexTable index_table_;
    NoiseProtocol protocol_;
    TimerManager timers_;
    LoadMonitor load_monitor_;
    std::unique_ptr<UdpSocket> socket_;
    std::unique_ptr<Sender> sender_;
    std::unique_ptr<Receiver> receiver_;
    PacketCallback packet_callback_;
    ReceiveEventCallback receive_event_callback_;
    Logger* logger_ = &Logger::default_logger();
    std::thread worker_;
    mutable std::mutex mutex_;
    std::atomic_bool running_{false};
};
}  // namespace wg
#endif  // CORE_HPP
