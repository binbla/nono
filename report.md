# 代码检查报告

检查范围：当前协议层实现，重点覆盖 `NoiseProtocol`、`noise` 封装、收发层、消息解析、cookie、transport/replay。按你的说明，本报告不把 `core` 核心调度未实现本身作为问题，只检查已经实现的协议逻辑。

验证情况：

- 直接编译探针通过：`g++ -std=c++20 -Iinclude src/core.cpp src/send.cpp src/receive.cpp src/protocol.cpp src/noise.cpp src/crypto.cpp -lsodium -c`
- 仓库没有发现 `CMakeLists.txt` / `Makefile` 等正式构建脚本。
- 未审查第三方目录 `external/BLAKE2` 的内部实现。

## 关键结论

当前协议骨架已经比较完整，但握手核心 transcript/KDF 逻辑存在高严重度问题：即使 core 调度补齐，双方也很可能无法稳定完成 Noise 握手；更重要的是，有几处失败返回被忽略，可能在密码学步骤失败后继续派生/安装错误 keypair。

建议先修复 `noise.cpp` 的 Noise 状态推进，再修 `protocol.cpp` 的返回值检查和状态机前置条件，最后补 cookie challenge 与边界测试。

## Findings

### 1. `mix_ephemeral()` 错误使用 KDF2，并覆盖 transcript hash

位置：`src/noise.cpp:73`

`mix_ephemeral()` 的注释写的是：

```cpp
Ci := Kdf1(Ci, Epub_i)
Hi := Hash(Hi || msg.ephemeral)
```

但实现是：

```cpp
mix_key(chaining_key, hash, ephemeral_public);
mix_hash(hash, ephemeral_public);
```

这里调用的是 `mix_key(ChainingKey&, SymmetricKey&, input)`，语义是 KDF2，并把第二个输出写入 `hash`。这会先把 transcript hash 覆盖成 KDF 输出，然后再混入 ephemeral public。Noise/WireGuard 的 `e` 步应当只用 KDF1 推进 chaining key，并在原 transcript hash 上追加 ephemeral public。

影响：

- 发起方和响应方的 `hash` / `chaining_key` 从第一步就偏离预期。
- 后续 `EncryptAndHash` 的 AD 错误，握手消息可能无法被正确解密。
- 即使两端都使用同一错误实现，也会偏离 WireGuard/Noise IKpsk2 语义，难以互操作和测试。

建议：

```cpp
void mix_ephemeral(const PublicKey& ephemeral_public,
                   ChainingKey& chaining_key,
                   Hash& hash) {
    mix_key(chaining_key, std::span<const uint8_t>(
        ephemeral_public.data(), ephemeral_public.size()));
    mix_hash(hash, ephemeral_public);
}
```

### 2. `base_hash_self_` 没有混入本地静态公钥，responder 消费 initiation 的初始 hash 错误

位置：`src/noise.cpp:8`, `src/noise.cpp:23`, `src/protocol.cpp:44`, `src/protocol.cpp:146`

`initialize_base()` 的注释要求：

```cpp
base_hash_self = HASH(base_hash || local_static)
```

但函数签名没有接收 `local_static`，实现也只是再次计算：

```cpp
HASH(base_chaining_key || identifier)
```

所以 `base_hash_self_` 实际等于 `base_hash_`，没有包含本地公钥。`consume_initiation()` 又用 `base_hash_self_` 作为 responder 侧初始 hash，导致 responder 解密 initiator static 时使用的 AD 与 initiator 创建消息时的 `peer.base_hash_peer()` 不一致。

影响：

- 正常 initiation 可能在 `decrypt_and_hash(remote_static, ...)` 阶段失败。
- 这是握手路径的阻断级问题。

建议：

- 让 `initialize_base()` 只返回 `base_chaining_key` 和 `base_hash`。
- 在 `NoiseProtocol::initialize()` 中执行 `crypto::hash_concat(base_hash_, local_public_, base_hash_self_)`。
- 或者把 `local_public` 传入 `initialize_base()`，但要避免函数注释和实现再次漂移。

### 3. 多个密码学步骤返回值被忽略，失败后仍继续安装握手状态或 keypair

位置：`src/protocol.cpp:108`, `src/protocol.cpp:112`, `src/protocol.cpp:114`, `src/protocol.cpp:116`, `src/protocol.cpp:119`, `src/protocol.cpp:235`, `src/protocol.cpp:239`, `src/protocol.cpp:241`, `src/protocol.cpp:245`, `src/protocol.cpp:318`, `src/protocol.cpp:320`, `src/protocol.cpp:375`

`generate_ephemeral_keypair()`、`mix_dh()`、`mix_precomputed_dh()`、`encrypt_and_hash()`、`aead_encrypt()` 都有失败语义，但创建握手/响应/transport 时基本没有检查返回值。

影响：

- 随机数失败、非法公钥、all-zero DH、AEAD 参数错误时，函数仍可能返回 `true`。
- 会把零值或旧值密钥写入 `Keypair`，并推进握手状态。
- transport 加密失败时仍返回成功，发送方可能发出全 0 或未认证的 ciphertext buffer。

建议：

- 所有返回 `bool` 的 crypto/noise 调用都要短路失败。
- 失败路径统一清理 `key`、`ephemeral_private`、`chaining_key` 等敏感临时变量。
- `create_datatrans()` 应在 AEAD 失败时不推进 `last_used_at`，并返回 `false`。

### 4. `create_response()` 没有执行注释里要求的握手状态检查

位置：`src/protocol.cpp:208`

注释写明创建 response 前要确认状态为 `ConsumedInitiation`，但实现没有检查：

```cpp
Handshake& hs = peer.handshake();
...
msg.receiver_index = hs.remote_index;
...
noise::mix_dh(..., hs.remote_ephemeral);
```

如果上层误调用，或者 core 调度边界尚未完全可靠，这里会用零值 `remote_index` / `remote_ephemeral` 创建响应，并可能安装错误 keypair。

影响：

- 状态机不闭合，协议层无法自保护。
- 错误调用会生成不可用或安全属性不明确的 response。

建议：

在 `create_response()` 开头检查：

```cpp
if (!initialized_ || hs.state != HandshakeState::ConsumedInitiation ||
    hs.remote_index == 0 || crypto::is_all_zero(hs.remote_ephemeral)) {
    return false;
}
```

也建议 `create_initiation()`、`create_datatrans()` 增加 `initialized_`、keypair owner/index 等基础检查。

### 5. CookieReply 解密结果未检查，伪造 cookie reply 会污染下一次握手

位置：`src/receive.cpp:206`

`consume_cookie_reply()` 调用：

```cpp
crypto::xaead_decrypt(..., cookie);
hs.last_cookie = cookie;
return ConsumedCookieReply;
```

但没有检查 `xaead_decrypt()` 的返回值。攻击者可以发送伪造 CookieReply，使本地保存一个全 0 或未认证 cookie，随后发起的握手会带上错误 mac2。

影响：

- cookie 状态可被网络垃圾包污染。
- 高负载场景下可能导致合法握手重试失败。

建议：

- 检查解密返回值，失败时返回 `CryptoFailed` 或 `InvalidMac2`，不要更新 `hs.last_cookie`。
- 解密前确认 `hs.last_mac1` 非零，否则也应丢弃。

### 6. 高负载 mac2 缺失/错误时只丢包，没有发送 CookieReply

位置：`src/receive.cpp:127`, `src/receive.cpp:136`, `src/receive.cpp:155`, `src/receive.cpp:163`

`Receiver` 的接口和注释都提到高负载下应触发 CookieReply，`Sender::send_cookie_reply()` 也已经实现。但当前 `consume_initiation()` / `consume_response()` 在 `needs_mac2_validation()` 为真且 mac2 无效时直接返回 `InvalidMac2`，没有使用传入的 `socket` 发送 cookie challenge。`consume_response()` 甚至没有 `UdpSocket&` 参数，因此 response 路径也无法发送 CookieReply。

影响：

- 高负载保护协议不可用：对端收不到 cookie challenge，就无法带正确 mac2 重试。
- 当前 readme 中提到的 cookie require 逻辑确实还没有闭环。

建议：

- mac1 有效但 mac2 缺失/无效时，调用 `Sender::send_cookie_reply()` 或把 cookie reply 生成逻辑抽到 receive 层。
- 对 initiation 和 response 都支持 cookie challenge。
- 返回 `ReceiveAction::SentCookieReply`，方便 core 做统计/日志。

### 7. `create_datatrans()` 在检查 payload 上限前构造越界 span

位置：`src/protocol.cpp:353`, `src/protocol.cpp:372`

`TransportData::encrypted_data` 固定为 `PAYLOAD_MAX_SIZE + TAG_SIZE`，但 `create_datatrans()` 没有检查 `data.size() <= PAYLOAD_MAX_SIZE`，直接：

```cpp
const size_t ciphertext_size = data.size() + TAG_SIZE;
std::span<uint8_t> ciphertext(msg.encrypted_data.data(), ciphertext_size);
```

`Sender::serialize_transport()` 虽然会检查 plaintext 大小，但它发生在 `create_datatrans()` 之后，太晚了。

影响：

- 上层传入超大 plaintext 时会形成越界 span，后续 AEAD 写入可能越界。
- 这是协议层函数本身的内存安全边界问题。

建议：

在 `create_datatrans()` 最开始检查：

```cpp
if (!initialized_ || data.size() > PAYLOAD_MAX_SIZE) {
    return false;
}
```

### 8. 固定长度消息解析接受尾随字节，与注释和协议固定长度语义不一致

位置：`src/receive.cpp:250`, `src/receive.cpp:258`, `src/receive.cpp:266`

注释写的是“packet 长度必须精确等于对应结构体大小”，但实现只检查 `< sizeof(...)`，长包会被截断解析并接受。transport 是变长包，固定握手消息不是。

影响：

- 可能接受非规范 wire 数据，给测试和互操作带来歧义。
- 如果上层按原始 datagram 做日志/统计，解析层和真实网络包语义不一致。

建议：

将 initiation/response/cookie reply 的长度检查改为 `packet.size() == sizeof(Message)`。

### 9. Replay 失败被映射成通用 `CryptoFailed`

位置：`src/protocol.cpp:420`, `src/receive.cpp:238`

`consume_datatrans()` 内部能区分 AEAD 失败和 replay 失败，但对外只返回 `false`，`Receiver::consume_transport()` 统一映射为 `ReceiveError::CryptoFailed`。

影响：

- core 后续很难对 replay、旧包、认证失败分别做统计和告警。
- 测试也无法断言 replay 窗口行为。

建议：

让协议层返回更细的结果枚举，或在 receive 层先用 `ReplayCounter::would_accept()` 辅助区分。注意仍应保持“AEAD 成功后才提交 replay 窗口”的当前顺序，这一点现在是对的。

## 建议修复顺序

1. 修 `noise::mix_ephemeral()` 和 `base_hash_self_`，这是握手能否成立的基础。
2. 给 `protocol.cpp` 所有 crypto/noise 返回值加短路处理和清理路径。
3. 给 `create_response()` / `create_initiation()` / `create_datatrans()` 补状态和边界检查。
4. 修 CookieReply 解密返回值检查，并补高负载 mac2 challenge 闭环。
5. 调整固定消息长度解析为精确匹配。
6. 增加最小协议测试：A/B 双端生成身份、互相注册 peer、initiation -> response -> 第一条 transport、replay 同 counter 失败、超大 payload 失败、伪造 CookieReply 不污染 cookie。

