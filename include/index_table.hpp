#ifndef INDEX_TABLE_HPP
#define INDEX_TABLE_HPP

#include <cstddef>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

#include "keypair.hpp"
#include "types.hpp"

namespace wg {

class IndexTable {
    // IndexTable 只负责index 索引：
    // 收包时根据 receive index 找到对应 Keypair。
    // 它不拥有 Keypair，也不负责创建、销毁、轮换或过期 Keypair。
   public:
    IndexTable() = default;
    ~IndexTable() = default;

    IndexTable(const IndexTable&) = delete;
    IndexTable& operator=(const IndexTable&) = delete;

    IndexTable(IndexTable&&) = delete;
    IndexTable& operator=(IndexTable&&) = delete;

    // 查找失败返回 nullptr，调用方据此判断未知 index。
    Keypair* find(KeypairIndex idx) const {
        std::lock_guard<std::mutex> lg(mutex_);
        auto it = keypairs_.find(idx);
        return it == keypairs_.end() ? nullptr : it->second;
    }

    bool contains(KeypairIndex idx) const {
        std::lock_guard<std::mutex> lg(mutex_);
        return keypairs_.find(idx) != keypairs_.end();
    }

    // 新增映射；已有同 index 时失败，不会覆盖。
    bool add(KeypairIndex idx, Keypair* keypair) {
        if (keypair == nullptr) {
            return false;
        }

        std::lock_guard<std::mutex> lg(mutex_);
        return keypairs_.emplace(idx, keypair).second;
    }

    // 只更新已有映射；index 不存在时失败。
    bool update(KeypairIndex idx, Keypair* keypair) {
        if (keypair == nullptr) {
            return false;
        }

        std::lock_guard<std::mutex> lg(mutex_);
        auto it = keypairs_.find(idx);
        if (it == keypairs_.end()) {
            return false;
        }

        it->second = keypair;
        return true;
    }

    // 新增或覆盖映射；返回旧值，没有旧值时返回 nullptr。
    Keypair* set(KeypairIndex idx, Keypair* keypair) {
        if (keypair == nullptr) {
            return nullptr;
        }

        std::lock_guard<std::mutex> lg(mutex_);
        auto it = keypairs_.find(idx);
        if (it == keypairs_.end()) {
            keypairs_.emplace(idx, keypair);
            return nullptr;
        }

        Keypair* old = it->second;
        it->second = keypair;
        return old;
    }

    // 移除映射但不释放 Keypair；调用方仍然负责对象生命周期。
    Keypair* erase(KeypairIndex idx) {
        std::lock_guard<std::mutex> lg(mutex_);
        auto it = keypairs_.find(idx);
        if (it == keypairs_.end()) {
            return nullptr;
        }

        Keypair* keypair = it->second;
        keypairs_.erase(it);
        return keypair;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lg(mutex_);
        return keypairs_.size();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lg(mutex_);
        return keypairs_.empty();
    }

    void clear() {
        std::lock_guard<std::mutex> lg(mutex_);
        keypairs_.clear();
    }

   private:
    mutable std::mutex mutex_;
    // 非拥有指针：Keypair 的生命周期由 KeypairManager / Core 负责。
    std::map<KeypairIndex, Keypair*> keypairs_;
};

}  // namespace wg

#endif  // INDEX_TABLE_HPP
