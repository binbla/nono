#ifndef KEYPAIR_MANAGER_HPP
#define KEYPAIR_MANAGER_HPP
#include <memory>

#include "keypair.hpp"
namespace wg {
class KeypairManager {
    // 三个 keypair 插槽：current/previous/next
   public:
    using Ptr = std::shared_ptr<Keypair>;  // 注意生命周期

    Ptr current() const { return current_; }
    Ptr previous() const { return previous_; }
    Ptr next() const { return next_; }

    // 正在握手流程的 keypair

    void clear() {
        current_.reset();
        previous_.reset();
        next_.reset();
    }

    // 安装新的 keypair，放在 next 插槽，等待轮转
    void install_new(Ptr kp) {
        if (!kp) return;
        next_ = std::move(kp);
    }

    bool rotate() {
        if (!next_) {
            return false;
        }
        previous_ = current_;
        current_ = next_;
        next_.reset();
        current_->is_activated = true;
        return true;
    }
    // keypair 的有效性则由上层去验证，不然写crontab定时任务来清理会有些麻烦。
    // 通过created_at和last_used_at来判断keypair是否过期，或者是否长时间未使用。
   private:
    Ptr current_;
    Ptr previous_;
    Ptr next_;
};
}  // namespace wg
#endif  // KEYPAIR_MANAGER_HPP

/*
1. 发送消息能遇到的情况
- current keypair 可用，发送
- current keypair 不可用，新走握手

2. 接收消息能遇到的情况
- 握手消息，按照握手流程处理
- 数据消息，检查keypair是否可用：
    - 可用，正常处理
    - 不可用，丢弃

nono
协议不关心可靠性，只关心可信性，所以不需要重试机制，也不需要对丢弃的消息进行任何处理。
对端的可靠层在没有收到预期回复的时候会自己重试或怎么处理。
这种冷处理和wireguard的设计是一致的

总结就是
发送消息：建立并返回一个可用的信道
收到信息：丢弃或正常处理

*/