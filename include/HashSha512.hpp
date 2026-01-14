// SHA-512 implementation.
//
// Copyright (c) 2024 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <stdint.h>
#include <vector>
#include <algorithm>
#include <cstring>

/// SHA-512 implementation according to FIPS PUB 180-4.
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class HashSha512
{
public:
    HashSha512()
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
        size_t bufferedBytes = messageLength & 0x7f;
        if ((bufferedBytes > 0) && (bufferedBytes + n >= 128))
        {
            size_t consumedBytes = 128 - bufferedBytes;
            std::copy(bytes, bytes + consumedBytes, buffer + bufferedBytes);
            processBlock(buffer);
            messageLength += consumedBytes;
            bytes += consumedBytes;
            n -= consumedBytes;
            bufferedBytes = 0;
        }

        // Process whole blocks of input.
        for (; n >= 128; bytes += 128, messageLength += 128, n -= 128)
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
        size_t bufferedBytes = messageLength & 0x7f;
        buffer[bufferedBytes] = 0x80;
        memset(buffer + bufferedBytes + 1, 0, 128 - bufferedBytes - 1);
        if (bufferedBytes + 17 > 128)
        {
            processBlock(buffer);
            memset(buffer, 0, 128 - 16);
        }
        uint64_t *buffer64 = reinterpret_cast<uint64_t *>(buffer);
        buffer64[14] = byteSwap64LE(messageLength >> 61);
        buffer64[15] = byteSwap64LE(messageLength << 3);
        processBlock(buffer);

        // Return hash.
        std::vector<uint8_t> r(64);
        uint64_t *data = reinterpret_cast<uint64_t *>(r.data());
        for (unsigned i = 0; i < 8; i++)
        {
            *(data++) = byteSwap64LE(state[i]);
        }
        clear();
        return r;
    }

private:
    /// Reverse bytes in 64-bit word on little-endian machines.
    uint64_t byteSwap64LE(uint64_t x)
    {
#ifdef __BIG_ENDIAN__
        return x;
#else
        x = ((x & 0x00000000ffffffffull) << 32) | ((x & 0xffffffff00000000ull) >> 32);
        x = ((x & 0x0000ffff0000ffffull) << 16) | ((x & 0xffff0000ffff0000ull) >> 16);
        return ((x & 0x00ff00ff00ff00ffull) << 8) | ((x & 0xff00ff00ff00ff00ull) >> 8);
#endif
    }

    /// Helper functions.
    static uint64_t Sig0(uint64_t x) { return std::rotr(x, 28) ^ std::rotr(x, 34) ^ std::rotr(x, 39); }
    static uint64_t Sig1(uint64_t x) { return std::rotr(x, 14) ^ std::rotr(x, 18) ^ std::rotr(x, 41); }
    static uint64_t sig0(uint64_t x) { return std::rotr(x, 1) ^ std::rotr(x, 8) ^ (x >> 7); }
    static uint64_t sig1(uint64_t x) { return std::rotr(x, 19) ^ std::rotr(x, 61) ^ (x >> 6); }
    static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ ((~x) & z); }
    static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }

    /// Process block.
    void processBlock(const uint8_t *data)
    {
        uint64_t a = state[0];
        uint64_t b = state[1];
        uint64_t c = state[2];
        uint64_t d = state[3];
        uint64_t e = state[4];
        uint64_t f = state[5];
        uint64_t g = state[6];
        uint64_t h = state[7];

        uint64_t W[16];
        for (unsigned t = 0; t < 16; t++)
        {
            W[t] = byteSwap64LE(*reinterpret_cast<const uint64_t *>(data));
            data += 8;
            uint64_t T1 = h + Sig1(e) + Ch(e, f, g) + K512[t] + W[t];
            uint64_t T2 = Sig0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        for (unsigned t = 16; t < 80; t++)
        {
            W[t & 0xf] += sig0(W[(t + 1) & 0x0f]) + sig1(W[(t + 14) & 0x0f]) + W[(t + 9) & 0xf];
            uint64_t T1 = h + Sig1(e) + Ch(e, f, g) + K512[t] + W[t & 0xf];
            uint64_t T2 = Sig0(a) + Maj(a, b, c);
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

    static constexpr uint64_t K512[] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

    /// Initial state.
    static constexpr uint64_t initialState[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

    /// State.
    uint64_t state[8];

    /// Input data buffer.
    uint8_t buffer[128];

    /// Message length in bytes.
    size_t messageLength;
};
