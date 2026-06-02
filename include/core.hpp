#ifndef CORE_HPP
#define CORE_HPP
#include "endpoint.hpp"
#include "index_table.hpp"
#include "peer.hpp"
#include "peer_manager.hpp"
#include "protocol.hpp"
#include "receive.hpp"
#include "send.hpp"
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

    // ------------------------------------------------------------
    // 接收接口
    // ------------------------------------------------------------

    // 如果你做同步 poll，可以暴露这个。
    ReceiveResult poll_once();

    // 如果你做 callback，则注册上层回调。
    void set_packet_callback(auto cb) { (void)cb; }

    // ------------------------------------------------------------
    // 定时器 / 状态推进
    // ------------------------------------------------------------

    void tick();

    // ------------------------------------------------------------
    // 资源访问，给内部模块或测试使用
    // ------------------------------------------------------------

    PeerManager& peer_manager();
    IndexTable& index_table();
    NoiseProtocol& protocol();
};
}  // namespace wg
#endif  // CORE_HPP