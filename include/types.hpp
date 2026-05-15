#ifndef TYPES_HPP
#define TYPES_HPP
#pragma once

#include <array>
#include <cfloat>   // 浮点类型极限
#include <climits>  // 整数类型极限
#include <cstddef>  //常用类型
#include <cstdint>  // 定长整数类型
#include <cstdlib>  // 通用工具

namespace wg {
// 假设MTU为1500
// 1 + 3 + 4 + 8 (head) + 16(tag) + 1420(payload) = 1452 bytes，外层还有IP/UDP头
// IPv4: 1452 + 20 (IP) + 8 (UDP) = 1480 bytes，适合MTU 1500
// IPv6: 1452 + 40 (IP) + 8 (UDP) = 1500 bytes，适合MTU 1500
constexpr size_t PAYLOAD_MAX_SIZE = 1420;  // 单数据包最大负载 根据MTU调整
// 常量
constexpr size_t KEY_SIZE = 32;            // For both public and private keys
constexpr size_t PUBLIC_KEY_SIZE = 32;     // X25519 public key size
constexpr size_t PRIVATE_KEY_SIZE = 32;    // X25519 private key size
constexpr size_t SYMMETRIC_KEY_SIZE = 32;  // ChaCha20-Poly1305 key size
constexpr size_t CHAINING_KEY_SIZE = 32;   // Chaining key size
constexpr size_t PSK_SIZE = 32;            // Pre-shared key size

constexpr size_t TIMESTAMP_SIZE = 12;  // 8 bytes timestamp + 4 bytes noise
constexpr size_t COUNTER_SIZE = 8;     // 64-bit packet counter
constexpr size_t TAG_SIZE = 16;        // Poly1305 authentication tag
constexpr size_t NONCE_SIZE = 12;      // ChaCha20-Poly1305 nonce size
constexpr size_t XNONCE_SIZE = 24;     // XChaCha20 nonce size
constexpr size_t HASH_SIZE = 32;       // BLAKE2s hash output size
constexpr size_t HMAC_SIZE = 32;       // HMAC-BLAKE2s output size (32 bytes)
constexpr size_t MAC_SIZE = 16;     // BLAKE2s MAC size (16 bytes for keyed MAC)
constexpr size_t COOKIE_SIZE = 16;  // WireGuard cookie size
constexpr size_t BLOCK_SIZE = 64;   // BLAKE2s block size

// 时间相关常量
constexpr size_t REKEY_AFTER_MESSAGES = 1ULL << 60;   // 主动rekey
constexpr size_t REJECT_AFTER_MESSAGES = 1ULL << 63;  // 直接拒绝
// 超过120秒的keypair会被主动rekey，超过180秒的keypair会被直接拒绝
constexpr uint64_t REKEY_AFTER_TIME = 120;   // seconds，resp主动rekey
constexpr uint64_t REJECT_AFTER_TIME = 180;  // seconds，直接拒绝
// 自握手开始算起，超过90秒还没完成就不再尝试，超过5秒没完成就重试
constexpr uint64_t REKEY_ATTEMPT_TIME = 90;  // seconds，handshake
constexpr uint64_t REKEY_TIMEOUT = 5;        // seconds，handshake超时重试
// 保活，大概就是10妙主动发一个包，更新对方的keypair的last_used_at，防止被清理掉
// 双端都会主动发
constexpr uint64_t KEEPALIVE_TIMEOUT = 10;  // seconds，keepalive超时
constexpr size_t WINDOW_SIZE = 8192;        // replay window size

constexpr uint64_t kInitiationMinInterval = 5;  // 同一peer发起握手的最小间隔

// 别名
using PublicKey = std::array<uint8_t, PUBLIC_KEY_SIZE>;        // STATIC_PUBLIC
using PrivateKey = std::array<uint8_t, PRIVATE_KEY_SIZE>;      // STATIC_PRIVATE
using SymmetricKey = std::array<uint8_t, SYMMETRIC_KEY_SIZE>;  // AEAD key
using ChainingKey = std::array<uint8_t, CHAINING_KEY_SIZE>;    // CK
using PreSharedKey = std::array<uint8_t, PSK_SIZE>;            // PSK
using Hash = std::array<uint8_t, HASH_SIZE>;         // Blake2s hash 32
using SharedSecret = std::array<uint8_t, KEY_SIZE>;  // DH 结果
using KeypairIndex = uint32_t;                       // keypair 的索引，32位
using Tag = std::array<uint8_t, TAG_SIZE>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;
using XNonce = std::array<uint8_t, XNONCE_SIZE>;
using Mac = std::array<uint8_t, MAC_SIZE>;    // Keyed-Blake2s 16
using Hmac = std::array<uint8_t, HMAC_SIZE>;  // Hmac-Blake2s 32

using Bytes32 = std::array<uint8_t, 32>;  // 有些中间变量需要不特指某种类型

}  // namespace wg

#endif  // TYPES_HPP