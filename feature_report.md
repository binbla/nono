# Keypair / Peer 功能报告

## 范围

本报告基于以下四个头文件：

- `include/keypair.hpp`
- `include/keypair_manager.hpp`
- `include/peer.hpp`
- `include/peer_manager.hpp`

这组模块围绕 WireGuard/Noise 风格的对端会话管理展开，核心目标是把“对端身份”“握手状态”“会话密钥生命周期”和“peer 索引”拆成清晰的运行时对象。

## 总体架构

系统可以分为两层：

1. 单个 peer 的运行时状态层
   - `Peer` 保存一个远端对等体的身份、预共享密钥、endpoint、握手状态和 keypair 管理器。
   - `Keypair` 保存一次会话的收发密钥、索引、计数器、防重放窗口和生命周期状态。
   - `KeypairManager` 在单个 peer 内维护 `previous/current/next` 三个 keypair 插槽。

2. 多 peer 的身份索引层
   - `PeerManager` 使用远端长期静态公钥作为稳定 key。
   - manager 只负责查找、添加、删除 peer，不介入握手、endpoint 或 keypair 细节。

整体关系如下：

```text
PeerManager
  map<PublicKey, unique_ptr<Peer>>
                         |
                         v
                      Peer
        +----------------+----------------+
        |                |                |
   Handshake       KeypairManager      endpoint/config/cache
                        |
          +-------------+-------------+
          |             |             |
       previous       current        next
          |             |             |
       Keypair       Keypair       Keypair
```

## Keypair

`Keypair` 表示一次已经或即将建立的加密会话。它包含收发方向的对称密钥、双方索引、计数器、防重放窗口和生命周期判断逻辑。

### 主要职责

- 保存发送密钥 `sending_` 和接收密钥 `receiving_`。
- 记录本端索引 `local_index` 和对端索引 `remote_index`。
- 关联所属 peer：`Peer* owner`。
- 记录创建时间 `created_at` 和最后使用时间 `last_used_at`。
- 使用原子计数器维护发送/接收包序号：
  - `sending_counter`
  - `receiving_counter`
- 保存握手相关的临时认证材料：
  - `last_mac1`
  - `last_cookie`
- 标记本端是否为握手发起方：`i_am_the_initiator`。
- 标记 keypair 是否已激活：`is_activated`。
- 通过 `ReplayCounter` 执行接收包防重放检查。

### 安全清理

`Keypair` 禁止拷贝和移动，避免密钥材料被意外复制或转移后留下不可控副本。析构函数会调用 `crypto::secure_zero()` 清零发送和接收密钥。

`clear_runtime()` 用于清理运行时状态，当前会：

- 清零接收密钥。
- 重置本端/对端索引。
- 清理 `last_used_at`。
- 重置发送/接收计数器。
- 重置 replay 窗口。
- 取消 initiator 和 activated 标记。

需要注意的是，当前代码中 `sending_`、`owner`、`created_at`、`last_mac1`、`last_cookie` 的清理语句被注释掉了。这说明该函数可能被设计为“部分复用/失效化”而不是完全销毁；如果后续把它作为彻底清理接口使用，应重新确认这些字段是否也需要清理。

### 可发送判断

`is_sendable()` 判断当前 keypair 是否可用于发送数据：

- 必须已经激活。
- 创建时间不能超过 `REKEY_AFTER_TIME`，当前为 120 秒。
- 发送计数不能超过 `REKEY_AFTER_MESSAGES`，当前为 `1ULL << 60`。

超过主动 rekey 条件后，该 keypair 不再适合作为发送 keypair，上层应触发新握手或 keypair 轮转。

### 可接收判断

`is_receivable()` 判断当前 keypair 是否可用于接收数据：

- 必须已经激活。
- 创建时间不能超过 `REJECT_AFTER_TIME`，当前为 180 秒。
- 接收计数不能超过 `REJECT_AFTER_MESSAGES`，当前为 `1ULL << 63`。

接收侧的拒绝阈值比发送侧更宽松，符合“发送端主动更新，接收端保留旧 keypair 一段时间以容忍乱序/延迟”的设计思路。

### 防重放

`check_replay(uint64_t counter)` 委托给 `ReplayCounter::check()`。调用语义是：在 AEAD 认证成功之后检查 counter 是否重复或落在窗口之外。窗口大小由 `WINDOW_SIZE` 控制，当前为 8192。

## KeypairManager

`KeypairManager` 是单个 peer 内部的 keypair 三槽管理器。

### 三个插槽

- `current`：当前用于发送/接收的主 keypair。
- `previous`：上一代 keypair，通常用于接收延迟到达的旧数据包。
- `next`：新握手产生但尚未轮转为 current 的 keypair。

三槽结构使 keypair 轮转变得明确：

```text
install_new(kp)
  next = kp

rotate()
  previous = current
  current = next
  next = null
  current.is_activated = true
```

### 生命周期管理

`KeypairManager` 使用 `std::shared_ptr<Keypair>`。这表示 keypair 的生命周期可能会被 manager 之外的流程共享，例如握手处理、包处理或异步发送路径。

`clear()` 会释放三个插槽的引用。具体 keypair 是否立即销毁，取决于外部是否仍持有 shared pointer。

### 行为边界

manager 不负责判断 keypair 是否过期或可用。有效性由 `Keypair::is_sendable()` / `is_receivable()` 和上层逻辑判断。这让 manager 保持简单，只承担安装和轮转职责。

## Peer

`Peer` 表示一个远端对等体，是身份信息、握手状态和 keypair 状态的聚合根。

### 配置输入

`PeerConfig` 描述一个离线定义的 peer：

- `remote_static`：远端长期静态公钥，也是 peer 的身份。
- `preshared_key`：可选预共享密钥材料，默认全 0。
- `endpoint`：可选远端网络地址。

### 构造行为

`Peer` 构造时保存配置，并预计算 `precomputed_mac1_hash_`：

```text
HASH("mac1----" || remote_static)
```

这用于后续 MAC1 计算，避免每次握手消息处理时重复拼接和哈希。

### 身份与配置接口

`Peer` 提供：

- `remote_static()` 获取远端长期公钥。
- `preshared_key()` / `set_preshared_key()` 获取或更新 PSK。
- `endpoint()` / `set_endpoint()` 获取或更新 endpoint。

### Noise / WireGuard 相关预计算

`Peer` 保存三个与远端身份绑定的预计算材料：

- `precomputed_static_static_`：本端静态私钥与远端静态公钥的 DH 结果缓存。
- `base_hash_`：与远端静态公钥混合后的基础握手 hash。
- `precomputed_mac1_hash_`：MAC1 计算相关缓存。

其中 `set_precomputed_static_static()` 在头文件中声明，但实现不在这四个文件内。该函数预计会同步更新长期 DH 结果，并可能派生或刷新 `base_hash_`。

### 运行时状态

`Peer` 内部静态持有：

- `Handshake handshake_`
- `KeypairManager keypairs_`

这种设计避免频繁 new/delete，并让 peer 成为握手状态与 keypair 状态的自然归属点。

此外，类中还预留了：

- `keepalive_interval`
- `tx_bytes`
- `rx_bytes`
- `is_alive`

这些字段当前是私有成员，尚未暴露操作接口，说明 keepalive、统计和存活状态可能还处于后续扩展阶段。

## PeerManager

`PeerManager` 是多 peer 容器，职责非常集中：用远端长期静态公钥索引 `Peer`。

### 数据结构

内部使用：

```cpp
std::map<PublicKey, std::unique_ptr<Peer>> peers_;
```

`PublicKey` 是 `std::array<uint8_t, 32>`，可直接作为 `std::map` key 进行字典序比较。

### 查找接口

- `find_by_public_key(const PublicKey&)`
- `find_by_public_key(const PublicKey&) const`
- `contains(const PublicKey&)`

查找失败返回 `nullptr`，调用方可据此判断是否为未知 peer。

### 添加接口

`PeerManager` 支持两种添加方式：

1. `add_peer(const PeerConfig& config)`
   - 根据配置创建新的 `Peer`。
   - 如果同公钥 peer 已存在，会替换旧对象。
   - 返回保存后的 `Peer&`。

2. `add_peer(std::unique_ptr<Peer> peer)`
   - 接管外部已构造好的 peer。
   - `nullptr` 会被忽略并返回 `nullptr`。
   - 如果同公钥 peer 已存在，也会替换旧对象。

### 删除和清空

- `remove_peer(const PublicKey&)` 删除指定 peer，返回是否真的删除。
- `clear()` 清空全部 peer。
- `size()` / `empty()` 提供容器状态查询。

### 行为边界

`PeerManager` 不处理：

- 握手状态推进。
- endpoint 更新策略。
- keypair 轮转。
- 数据包发送/接收。
- peer 存活性或统计。

这些状态都保留在 `Peer` 或更上层协议流程中。

## 典型流程

### 添加 peer

```text
读取配置
  -> 构造 PeerConfig
  -> PeerManager::add_peer(config)
  -> Peer 构造并预计算 mac1 hash
  -> 后续由上层补充静态 DH / base hash 等材料
```

### 握手生成新 keypair

```text
握手流程完成
  -> 创建 Keypair
  -> 填充 sending / receiving key
  -> 设置 local_index / remote_index / owner / created_at
  -> KeypairManager::install_new(kp)
  -> KeypairManager::rotate()
  -> next 变为 current，旧 current 变为 previous
  -> current.is_activated = true
```

### 发送数据

```text
根据 peer 找到 current keypair
  -> 调用 is_sendable()
  -> 若可用，使用 sending key 和 sending_counter 加密发送
  -> 若不可用，上层触发新握手或 rekey
```

### 接收数据

```text
根据包内索引或 peer 身份找到候选 keypair
  -> 调用 is_receivable()
  -> AEAD 认证成功后调用 check_replay(counter)
  -> 通过则接受数据，否则丢弃
```

## 设计特点

- 职责分离清晰：`PeerManager` 管身份索引，`Peer` 管单个对端状态，`KeypairManager` 管 keypair 三槽，`Keypair` 管单次会话密钥。
- 生命周期接近 WireGuard 模型：发送侧更早 rekey，接收侧更晚 reject。
- 密钥对象禁止拷贝/移动，减少敏感材料意外复制。
- 使用 `secure_zero()` 清理密钥材料，符合安全敏感对象的基本要求。
- 防重放逻辑封装在 `ReplayCounter` 中，`Keypair` 只暴露简洁检查接口。
- `PeerManager` 使用 `unique_ptr` 表达 peer 的唯一所有权，`KeypairManager` 使用 `shared_ptr` 表达 keypair 可能跨流程共享。

## 注意点与潜在改进

1. `Keypair::clear_runtime()` 当前没有清零 `sending_`

   析构函数会清零发送和接收密钥，但 `clear_runtime()` 中发送密钥清理被注释。如果该函数会在对象继续存活时表示“失效化”，建议确认是否应恢复 `crypto::secure_zero(sending_)`。

2. `Keypair::clear_runtime()` 没有清理 `created_at`

   如果后续逻辑依赖 `created_at` 判断有效期，旧时间残留可能影响复用场景。当前注释显示这是有意保留或尚未决定的行为，需要结合调用点确认。

3. `Peer` 中统计和 keepalive 字段尚无接口

   `keepalive_interval`、`tx_bytes`、`rx_bytes`、`is_alive` 已预留，但目前无法被外部读写。后续实现 keepalive 或统计时，需要补充明确接口或由上层状态机维护。

4. `PeerManager::add_peer()` 会静默替换同公钥 peer

   这对配置重载很方便，但如果误添加重复 peer，旧 peer 的握手和 keypair 状态会被直接丢弃。是否需要返回替换信息，取决于配置管理层的需求。

5. 线程安全边界需要上层明确

   `ReplayCounter` 内部有 mutex，`Keypair` 的计数器是 atomic，但 `KeypairManager` 和 `PeerManager` 本身没有锁。如果发送、接收、握手、配置更新跨线程并发运行，上层需要提供同步保护。

## 总结

这四个模块形成了一个小而完整的 peer/keypair 运行时模型：

- `PeerManager` 负责“找到哪个 peer”。
- `Peer` 负责“这个 peer 有哪些身份、握手和会话状态”。
- `KeypairManager` 负责“当前、上一代、下一代 keypair 如何轮转”。
- `Keypair` 负责“这次会话密钥是否还能安全发送/接收，以及是否遭遇重放”。

整体设计偏向轻量和显式状态管理，适合作为 Noise/WireGuard 风格协议实现中的 peer session 层。后续重点应放在 keypair 清理语义、并发同步边界、索引到 keypair 的查找路径，以及 keepalive/statistics 字段的完整接入。
