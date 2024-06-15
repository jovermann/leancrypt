// MD5 implementation.
//
// Copyright (c) 2024 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <algorithm>
#include <bit>

/// MD5 implementation according to RFC1321.
/// https://datatracker.ietf.org/doc/html/rfc1321
class HashMd5
{
public:
    HashMd5()
    {
        clear();
    }

    /// Initialize hasher.
    /// Call this after retrieving the hash and before calculating a new hash of new data.
    void clear()
    {
        std::copy(initialState, initialState + 4, state);
        messageLength = 0;
    }

    /// Add data.
    void update(const uint8_t *bytes, size_t n)
    {
        // Process buffered bytes if any and if one block is available.
        size_t bufferedBytes = messageLength & 0x3f;
        if ((bufferedBytes > 0) && (bufferedBytes + n >= 64))
        {
            size_t consumedBytes = 64 - bufferedBytes;
            std::copy(bytes, bytes + consumedBytes, buffer + bufferedBytes);
            processBlock(buffer);
            messageLength += consumedBytes;
            bytes += consumedBytes;
            n -= consumedBytes;
            bufferedBytes = 0;
        }

        // Process whole blocks of input.
        for (; n >= 64; bytes += 64, messageLength += 64, n -= 64)
        {
            processBlock(bytes);
        }

        // Put remaining bytes into buffer.
        std::copy(bytes, bytes + n, buffer + bufferedBytes);
        messageLength += n;
    }

    /// Get hash.
    std::vector<uint8_t> finalize()
    {
        // Pad message and calc final 1-2 blocks.
        size_t bufferedBytes = messageLength & 0x3f;
        buffer[bufferedBytes] = 0x80;
        memset(buffer + bufferedBytes + 1, 0, 64 - bufferedBytes - 1);
        if (bufferedBytes + 9 > 64)
        {
            processBlock(buffer);
            memset(buffer, 0, 64 - 8);
        }
        uint32_t *buffer32 = reinterpret_cast<uint32_t *>(buffer);
        buffer32[14] = byteSwap32BE(messageLength << 3);
        buffer32[15] = byteSwap32BE(messageLength >> 29);
        processBlock(buffer);

        // Return hash.
        std::vector<uint8_t> r(16);
        uint32_t *data = reinterpret_cast<uint32_t *>(r.data());
        for (unsigned i = 0; i < 4; i++)
        {
            *(data++) = byteSwap32BE(state[i]);
        }
        clear();
        return r;
    }

private:
    /// Reverse bytes in 32-bit word on big-endian machines.
    int32_t byteSwap32BE(uint32_t x)
    {
#ifdef __BIG_ENDIAN__
        x = ((x & 0x0000ffff) << 16) | ((x & 0xffff0000) >> 16);
        return ((x & 0x00ff00ff) << 8) | ((x & 0xff00ff00) >> 8);
#else
        return x;
#endif
    }

    /// Helper functions.
    static void FF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) { a += ((b & c) | ((~b) & d)) + x + ac; a = std::rotl(a, s); a += b; }
    static void GG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) { a += ((b & d) | (c & (~d))) + x + ac; a = std::rotl(a, s); a += b; }
    static void HH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) { a += (b ^ c ^ d)            + x + ac; a = std::rotl(a, s); a += b; }
    static void II(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) { a += (c ^ (b | (~d)))       + x + ac; a = std::rotl(a, s); a += b; }

    /// Process block.
    void processBlock(const uint8_t *data8)
    {
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];

        const uint32_t *data = reinterpret_cast<const uint32_t*>(data8);

        // 4 * 16 = 64 unrolled rounds.
        FF(a, b, c, d, data[ 0],  7, 0xd76aa478);
        FF(d, a, b, c, data[ 1], 12, 0xe8c7b756);
        FF(c, d, a, b, data[ 2], 17, 0x242070db);
        FF(b, c, d, a, data[ 3], 22, 0xc1bdceee);
        FF(a, b, c, d, data[ 4],  7, 0xf57c0faf);
        FF(d, a, b, c, data[ 5], 12, 0x4787c62a);
        FF(c, d, a, b, data[ 6], 17, 0xa8304613);
        FF(b, c, d, a, data[ 7], 22, 0xfd469501);
        FF(a, b, c, d, data[ 8],  7, 0x698098d8);
        FF(d, a, b, c, data[ 9], 12, 0x8b44f7af);
        FF(c, d, a, b, data[10], 17, 0xffff5bb1);
        FF(b, c, d, a, data[11], 22, 0x895cd7be);
        FF(a, b, c, d, data[12],  7, 0x6b901122);
        FF(d, a, b, c, data[13], 12, 0xfd987193);
        FF(c, d, a, b, data[14], 17, 0xa679438e);
        FF(b, c, d, a, data[15], 22, 0x49b40821);
        GG(a, b, c, d, data[ 1],  5, 0xf61e2562);
        GG(d, a, b, c, data[ 6],  9, 0xc040b340);
        GG(c, d, a, b, data[11], 14, 0x265e5a51);
        GG(b, c, d, a, data[ 0], 20, 0xe9b6c7aa);
        GG(a, b, c, d, data[ 5],  5, 0xd62f105d);
        GG(d, a, b, c, data[10],  9, 0x02441453);
        GG(c, d, a, b, data[15], 14, 0xd8a1e681);
        GG(b, c, d, a, data[ 4], 20, 0xe7d3fbc8);
        GG(a, b, c, d, data[ 9],  5, 0x21e1cde6);
        GG(d, a, b, c, data[14],  9, 0xc33707d6);
        GG(c, d, a, b, data[ 3], 14, 0xf4d50d87);
        GG(b, c, d, a, data[ 8], 20, 0x455a14ed);
        GG(a, b, c, d, data[13],  5, 0xa9e3e905);
        GG(d, a, b, c, data[ 2],  9, 0xfcefa3f8);
        GG(c, d, a, b, data[ 7], 14, 0x676f02d9);
        GG(b, c, d, a, data[12], 20, 0x8d2a4c8a);
        HH(a, b, c, d, data[ 5],  4, 0xfffa3942);
        HH(d, a, b, c, data[ 8], 11, 0x8771f681);
        HH(c, d, a, b, data[11], 16, 0x6d9d6122);
        HH(b, c, d, a, data[14], 23, 0xfde5380c);
        HH(a, b, c, d, data[ 1],  4, 0xa4beea44);
        HH(d, a, b, c, data[ 4], 11, 0x4bdecfa9);
        HH(c, d, a, b, data[ 7], 16, 0xf6bb4b60);
        HH(b, c, d, a, data[10], 23, 0xbebfbc70);
        HH(a, b, c, d, data[13],  4, 0x289b7ec6);
        HH(d, a, b, c, data[ 0], 11, 0xeaa127fa);
        HH(c, d, a, b, data[ 3], 16, 0xd4ef3085);
        HH(b, c, d, a, data[ 6], 23, 0x04881d05);
        HH(a, b, c, d, data[ 9],  4, 0xd9d4d039);
        HH(d, a, b, c, data[12], 11, 0xe6db99e5);
        HH(c, d, a, b, data[15], 16, 0x1fa27cf8);
        HH(b, c, d, a, data[ 2], 23, 0xc4ac5665);
        II(a, b, c, d, data[ 0],  6, 0xf4292244);
        II(d, a, b, c, data[ 7], 10, 0x432aff97);
        II(c, d, a, b, data[14], 15, 0xab9423a7);
        II(b, c, d, a, data[ 5], 21, 0xfc93a039);
        II(a, b, c, d, data[12],  6, 0x655b59c3);
        II(d, a, b, c, data[ 3], 10, 0x8f0ccc92);
        II(c, d, a, b, data[10], 15, 0xffeff47d);
        II(b, c, d, a, data[ 1], 21, 0x85845dd1);
        II(a, b, c, d, data[ 8],  6, 0x6fa87e4f);
        II(d, a, b, c, data[15], 10, 0xfe2ce6e0);
        II(c, d, a, b, data[ 6], 15, 0xa3014314);
        II(b, c, d, a, data[13], 21, 0x4e0811a1);
        II(a, b, c, d, data[ 4],  6, 0xf7537e82);
        II(d, a, b, c, data[11], 10, 0xbd3af235);
        II(c, d, a, b, data[ 2], 15, 0x2ad7d2bb);
        II(b, c, d, a, data[ 9], 21, 0xeb86d391);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    /// Initial state.
    static constexpr uint32_t initialState[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

    /// State.
    uint32_t state[4];

    /// Input data buffer.
    uint8_t buffer[64];

    /// Message length in bytes.
    size_t messageLength;
};
