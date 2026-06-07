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
// 协议栈的最高层，负责管理Peer和Keypair的生命周期，决定何时发起握手，何时重传，何时发数据包等
/*
1. 初始化协议栈
2. 管理本地身份
3. 管理 peers
4. 管理 UDP socket / 端口绑定 / 网络事件循环
5. 管理 index table
6. 管理发送入口
7. 管理接收入口
8. 管理握手触发、重试、keepalive、keypair 过期检查
9. 向上层暴露简单 send/recv API
*/
using PacketCallback =
    std::function<void(Peer& peer, std::span<const uint8_t> packet)>;
using ReceiveEventCallback = std::function<void(const ReceiveResult& result)>;
using WirePacketCallback = std::function<void(std::span<const uint8_t> packet)>;
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

    bool generate_identity_and_initialize();

    bool bind(const Endpoint& local_endpoint);

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

    SendResult begin_handshake(Peer& peer);

    SendResult begin_handshake(const PublicKey& remote_static);

    SendResult retry_handshake(Peer& peer);

    SendResult retry_handshake(const PublicKey& remote_static);

    // ------------------------------------------------------------
    // 接收接口
    // ------------------------------------------------------------

    // 如果你做同步 poll，可以暴露这个。
    ReceiveResult poll_once();

    // 如果你做 callback，则注册上层回调。
    void set_packet_callback(PacketCallback cb);

    void set_receive_event_callback(ReceiveEventCallback cb);

    void set_wire_packet_callback(WirePacketCallback cb);

    void set_logger(Logger* logger);

    // ------------------------------------------------------------
    // 定时器 / 状态推进
    // ------------------------------------------------------------

    void tick();

    void register_default_timers();

    void set_force_cookie_reply(bool force);

    TimerManager& timers();

    // ------------------------------------------------------------
    // 资源访问，给内部模块或测试使用
    // ------------------------------------------------------------

    PeerManager& peer_manager();
    IndexTable& index_table();
    NoiseProtocol& protocol();

   private:
    KeypairIndex allocate_index();
    Keypair* install_next_keypair(Peer& peer, bool i_am_the_initiator);
    SendResult initiate_handshake(Peer& peer);
    SendResult resend_response(Peer& peer, Keypair& keypair);
    void handle_receive_result(const ReceiveResult& result,
                               std::span<const uint8_t> plaintext);
    void run_loop();

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
