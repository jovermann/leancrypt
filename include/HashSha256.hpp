// SHA-256 implementation.
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

/// SHA-256 implementation according to FIPS PUB 180-4.
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class HashSha256
{
public:
    HashSha256()
    {
        clear();
    }

    /// Initialize hasher.
    /// Call this after retrieving the hash and before calculating a new hash of new data.
    void clear()
    {
        std::copy(initialState, initialState + 8, state);
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
        std::vector<uint8_t> r(32);
        uint32_t *data = reinterpret_cast<uint32_t *>(r.data());
        for (unsigned i = 0; i < 8; i++)
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
    static uint32_t Sig0(uint32_t x) { return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22); }
    static uint32_t Sig1(uint32_t x) { return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25); }
    static uint32_t sig0(uint32_t x) { return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3); }
    static uint32_t sig1(uint32_t x) { return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10); }
    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ ((~x) & z); }
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

    /// Process block.
    void processBlock(const uint8_t *data)
    {
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        uint32_t W[16];
        for (unsigned t = 0; t < 16; t++)
        {
            W[t] = byteSwap32LE(*reinterpret_cast<const uint32_t *>(data));
            data += 4;
            uint32_t T1 = h + Sig1(e) + Ch(e, f, g) + K256[t] + W[t];
            uint32_t T2 = Sig0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        for (unsigned t = 16; t < 64; t++)
        {
            W[t & 0xf] += sig0(W[(t + 1) & 0x0f]) + sig1(W[(t + 14) & 0x0f]) + W[(t + 9) & 0xf];
            uint32_t T1 = h + Sig1(e) + Ch(e, f, g) + K256[t] + W[t & 0xf];
            uint32_t T2 = Sig0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    static constexpr uint32_t K256[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /// Initial state.
    static constexpr uint32_t initialState[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    /// State.
    uint32_t state[8];

    /// Input data buffer.
    uint8_t buffer[64];

    /// Message length in bytes.
    size_t messageLength;
};
