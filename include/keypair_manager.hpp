#ifndef KEYPAIR_MANAGER_HPP
#define KEYPAIR_MANAGER_HPP
#include <memory>

#include "keypair.hpp"
namespace wg {
class KeypairManager {
    // 三个 keypair 插槽：current/previous/next
   public:
    using Ptr = std::shared_ptr<Keypair>;  // 注意生命周期

    // 三个外部接口：current/previous/next
    Ptr current() const { return current_; }
    Ptr previous() const { return previous_; }
    Ptr next() const { return next_; }

    void clear() {
        current_.reset();
        previous_.reset();
        next_.reset();
    }

    // 安装新的 keypair，放在 next 插槽
    // 挤掉原来的 next（如果有的话）
    KeypairIndex install_new(Ptr kp) {
        KeypairIndex idx = 0;
        if (next_) {
            idx = next_->local_index;
        }
        next_ = std::move(kp);
        return idx;
    }

    // 轮转 keypair：previous <- current <- next，next 变空。
    // 挤掉 previous 的 keypair（如果有的话）
    KeypairIndex rotate() {
        KeypairIndex idx = 0;
        if (previous_) {
            idx = previous_->local_index;
        }
        previous_ = current_;
        current_ = next_;
        next_.reset();
        current_->is_activated = true;
        return idx;
    }
    // 通过created_at和last_used_at来判断keypair是否过期，或者是否长时间未使用。
   private:
    Ptr current_;
    Ptr previous_;
    Ptr next_;
};
}  // namespace wg
#endif  // KEYPAIR_MANAGER_HPP
