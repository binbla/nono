#ifndef PEER_MANAGER_HPP
#define PEER_MANAGER_HPP

#include <cstddef>
#include <map>
#include <memory>
#include <utility>

#include "peer.hpp"
#include "types.hpp"
namespace wg {
class PeerManager {
    // PeerManager 只负责“身份索引”：
    // 用 peer 的长期静态公钥作为稳定 key，找到对应的运行时 Peer 对象。
    // keypair、握手、endpoint 等具体状态仍然放在 Peer 内部维护。
   public:
    // 查找失败返回 nullptr，调用方可以据此判断未知 peer。
    Peer* find_by_public_key(const PublicKey& key) {
        auto it = peers_.find(key);
        return it == peers_.end() ? nullptr : it->second.get();
    }

    const Peer* find_by_public_key(const PublicKey& key) const {
        auto it = peers_.find(key);
        return it == peers_.end() ? nullptr : it->second.get();
    }

    Peer* find_by_endpoint(const Endpoint& endpoint) {
        for (auto& [_, peer] : peers_) {
            if (peer->endpoint() && *peer->endpoint() == endpoint) {
                return peer.get();
            }
        }
        return nullptr;
    }

    const Peer* find_by_endpoint(const Endpoint& endpoint) const {
        for (const auto& [_, peer] : peers_) {
            if (peer->endpoint() && *peer->endpoint() == endpoint) {
                return peer.get();
            }
        }
        return nullptr;
    }

    bool contains(const PublicKey& key) const {
        return peers_.find(key) != peers_.end();
    }

    // 从配置直接创建 Peer；如果同公钥已存在，则替换旧对象。
    Peer& add_peer(const PeerConfig& config) {
        auto peer = std::make_unique<Peer>(config);
        Peer& ref = *peer;
        peers_[config.remote_static] = std::move(peer);
        return ref;
    }

    // 接管外部已经构造好的 Peer；nullptr 会被忽略。
    // 返回值是最终保存在 manager 里的对象指针。
    Peer* add_peer(std::unique_ptr<Peer> peer) {
        if (!peer) {
            return nullptr;
        }

        const PublicKey key = peer->remote_static();
        Peer* raw = peer.get();
        peers_[key] = std::move(peer);
        return raw;
    }

    // 返回 true 表示确实删除了一个 peer。
    bool remove_peer(const PublicKey& key) {
        return peers_.erase(key) != 0;
    }

    void clear() { peers_.clear(); }

    size_t size() const { return peers_.size(); }
    bool empty() const { return peers_.empty(); }

   private:
    // std::array<uint8_t, 32> 默认支持字典序比较，可直接作为 std::map 的 key。
    std::map<PublicKey, std::unique_ptr<Peer>> peers_;
};
}  // namespace wg
#endif  // PEER_MANAGER_HPP
