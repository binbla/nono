#ifndef MESSAGES_HPP
#define MESSAGES_HPP
#pragma once

#include <endian.h>
// 注意，多字节的数据结构统一按小端序存
/*
序列化
uint16_t v16 = htole16(x);
uint32_t v32 = htole32(x);
uint64_t v64 = htole64(x);
反序列化
x = le16toh(v16);
x = le32toh(v32);
x = le64toh(v64);

array 这种纯字节流不做处理
*/

#include <array>
#include <cstdint>
#include <vector>

#include "types.hpp"

namespace wg {
enum class MessageType : uint8_t {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
};

// 第一条消息：发起者至响应者
#pragma pack(push, 1)
struct HandshakeInitiation {
    MessageType message_type;    // 1
    uint8_t reserved[3];         // 3
    KeypairIndex sender_index;   // 4 - 发起者的索引
    PublicKey ephemeral_public;  // 32 - 发起者的临时公钥
    std::array<uint8_t, 48>
        static_encrypted;  // 48 - 加密的发起者静态公钥（32）+ AEAD TAG（16）
    std::array<uint8_t, 28>
        timestamp_encrypted;  // 28 - 加密的时间戳（12）+ AEAD TAG（16）
    Mac mac1;
    Mac mac2;
};
#pragma pack(pop)
static_assert(sizeof(HandshakeInitiation) == 148);

// 第二条消息：响应者至发起者
#pragma pack(push, 1)
struct HandshakeResponse {
    MessageType message_type;                 // 1
    uint8_t reserved[3];                      // 3
    KeypairIndex sender_index;                // 4
    KeypairIndex receiver_index;              // 4
    PublicKey ephemeral_public;               // 32
    std::array<uint8_t, 16> empty_encrypted;  // 16
    Mac mac1;                                 // 16
    Mac mac2;                                 // 16
};
#pragma pack(pop)
static_assert(sizeof(HandshakeResponse) == 92);

// Under load: Cookie Reply Message
#pragma pack(push, 1)
struct CookieReply {
    MessageType message_type;                                      // 1
    uint8_t reserved[3];                                           // 3
    KeypairIndex receiver_index;                                   // 4
    XNonce nonce;                                                  // 24
    std::array<uint8_t, COOKIE_SIZE + TAG_SIZE> encrypted_cookie;  // 16 +16
};
#pragma pack(pop)
static_assert(sizeof(CookieReply) == 64);

// 后续消息：双方至对方
#pragma pack(push, 1)
struct TransportDataHeader {
    MessageType message_type;     // 1
    uint8_t reserved[3];          // 3
    KeypairIndex receiver_index;  // 4
    uint64_t counter;             // 8 这个要做序列化 注意字节序
};
#pragma pack(pop)

struct TransportData {
    TransportDataHeader header;
    std::array<uint8_t, PAYLOAD_MAX_SIZE + TAG_SIZE> encrypted_data;
};
}  // namespace wg
#endif  // MESSAGES_HPP