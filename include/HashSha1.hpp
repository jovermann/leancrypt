// SHA-1 implementation.
//
// Copyright (c) 2024 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <stdint.h>
#include <vector>
#include <algorithm>
#include <bit>

/// SHA-1 implementation according to FIPS PUB 180-4.
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class HashSha1
{
public:
    HashSha1()
    {
        clear();
    }

    /// Initialize hasher.
    /// Call this after retrieving the hash and before calculating a new hash of new data.
    void clear()
    {
        std::copy(initialState, initialState + 5, state);
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
        buffer32[14] = byteSwap32LE(messageLength >> 29);
        buffer32[15] = byteSwap32LE(messageLength << 3);
        processBlock(buffer);

        // Return hash.
        std::vector<uint8_t> r(20);
        uint32_t *data = reinterpret_cast<uint32_t *>(r.data());
        for (unsigned i = 0; i < 5; i++)
        {
            *(data++) = byteSwap32LE(state[i]);
        }
        clear();
        return r;
    }

private:
    /// Reverse bytes in 32-bit word on little-endian machines.
    uint32_t byteSwap32LE(uint32_t x)
    {
#ifdef __BIG_ENDIAN__
        return x;
#else
        x = ((x & 0x0000ffff) << 16) | ((x & 0xffff0000) >> 16);
        return ((x & 0x00ff00ff) << 8) | ((x & 0xff00ff00) >> 8);
#endif
    }

    /// Helper functions.
    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ ((~x) & z); }
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t Par(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

    /// Process block.
    void processBlock(const uint8_t *data)
    {
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];

        uint32_t W[16];
        for (unsigned t = 0; t < 16; t++)
        {
            W[t] = byteSwap32LE(*reinterpret_cast<const uint32_t *>(data));
            data += 4;
            uint32_t T = std::rotl(a, 5) + Ch(b, c, d) + e + 0x5a827999 + W[t];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        for (unsigned t = 16; t < 20; t++)
        {
            W[t & 0xf] = std::rotl(W[(t + 13) & 0x0f] ^ W[(t + 8) & 0x0f] ^ W[(t + 2) & 0xf] ^ W[t & 0xf], 1);
            uint32_t T = std::rotl(a, 5) + Ch(b, c, d) + e + 0x5a827999 + W[t & 0xf];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        for (unsigned t = 20; t < 40; t++)
        {
            W[t & 0xf] = std::rotl(W[(t + 13) & 0x0f] ^ W[(t + 8) & 0x0f] ^ W[(t + 2) & 0xf] ^ W[t & 0xf], 1);
            uint32_t T = std::rotl(a, 5) + Par(b, c, d) + e + 0x6ed9eba1 + W[t & 0xf];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        for (unsigned t = 40; t < 60; t++)
        {
            W[t & 0xf] = std::rotl(W[(t + 13) & 0x0f] ^ W[(t + 8) & 0x0f] ^ W[(t + 2) & 0xf] ^ W[t & 0xf], 1);
            uint32_t T = std::rotl(a, 5) + Maj(b, c, d) + e + 0x8f1bbcdc + W[t & 0xf];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        for (unsigned t = 60; t < 80; t++)
        {
            W[t & 0xf] = std::rotl(W[(t + 13) & 0x0f] ^ W[(t + 8) & 0x0f] ^ W[(t + 2) & 0xf] ^ W[t & 0xf], 1);
            uint32_t T = std::rotl(a, 5) + Par(b, c, d) + e + 0xca62c1d6 + W[t & 0xf];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

    /// Initial state.
    static constexpr uint32_t initialState[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

    /// State.
    uint32_t state[5];

    /// Input data buffer.
    uint8_t buffer[64];

    /// Message length in bytes.
    size_t messageLength;
};
