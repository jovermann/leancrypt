// AES block cipher implementation.
//
// Copyright (c) 2026 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

/// AES block cipher according to FIPS PUB 197.
/// @tparam KeyBits AES key length in bits; must be 128 or 256.
/// This is a very simple, 100% portable C++ implementation intended for
/// readability. It uses no platform-specific acceleration and consequently
/// has rather low performance compared with optimized AES implementations.
/// It uses key-dependent table lookups and is not side-channel hardened.
/// The object expands and retains its key and can then encrypt or decrypt any
/// number of independent 16-byte blocks. This class does not provide a block
/// mode, padding, authentication, or nonce handling; use AesGcm for messages.
template<size_t KeyBits>
class Aes
{
    static_assert(KeyBits == 128 || KeyBits == 256, "AES supports 128-bit and 256-bit keys");

public:
    /// AES block length in bytes.
    static constexpr size_t blockSize = 16;

    /// AES key length in bytes for this template specialization.
    static constexpr size_t keySize = KeyBits / 8;

    /// Number of AES transformation rounds for this key length.
    static constexpr unsigned rounds = KeyBits == 128 ? 10 : 14;

    /// Fixed-size byte representation of one AES input or output block.
    using Block = std::array<uint8_t, blockSize>;

    /// Fixed-size byte representation of an AES key.
    using Key = std::array<uint8_t, keySize>;

    /// Construct a cipher and expand @p key for subsequent operations.
    /// @param key Exactly keySize bytes of key material.
    explicit Aes(const Key& key) { expandKey(key); }

    /// Construct a cipher from a dynamically sized key and expand it.
    /// @param key Key material, which must contain exactly keySize bytes.
    /// @throws std::invalid_argument if @p key has the wrong size.
    explicit Aes(std::span<const uint8_t> key)
    {
        if (key.size() != keySize)
            throw std::invalid_argument("Invalid AES key size");
        Key fixedKey{};
        std::copy(key.begin(), key.end(), fixedKey.begin());
        expandKey(fixedKey);
    }

    /// Encrypt one block using the expanded key.
    /// @param input The 16 plaintext bytes. The input is not modified.
    /// @return The corresponding 16-byte ciphertext block.
    Block encryptBlock(const Block& input) const
    {
        uint32_t s0 = get32(input.data()) ^ encryptionRoundKeys[0];
        uint32_t s1 = get32(input.data() + 4) ^ encryptionRoundKeys[1];
        uint32_t s2 = get32(input.data() + 8) ^ encryptionRoundKeys[2];
        uint32_t s3 = get32(input.data() + 12) ^ encryptionRoundKeys[3];
        for (unsigned round = 1; round < rounds; ++round)
        {
            const size_t key = 4 * round;
            const uint32_t t0 = encryptColumn(s0, s1, s2, s3) ^ encryptionRoundKeys[key];
            const uint32_t t1 = encryptColumn(s1, s2, s3, s0) ^ encryptionRoundKeys[key + 1];
            const uint32_t t2 = encryptColumn(s2, s3, s0, s1) ^ encryptionRoundKeys[key + 2];
            const uint32_t t3 = encryptColumn(s3, s0, s1, s2) ^ encryptionRoundKeys[key + 3];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }

        const size_t key = 4 * rounds;
        Block result{};
        put32(result, 0, finalEncryptColumn(s0, s1, s2, s3) ^ encryptionRoundKeys[key]);
        put32(result, 4, finalEncryptColumn(s1, s2, s3, s0) ^ encryptionRoundKeys[key + 1]);
        put32(result, 8, finalEncryptColumn(s2, s3, s0, s1) ^ encryptionRoundKeys[key + 2]);
        put32(result, 12, finalEncryptColumn(s3, s0, s1, s2) ^ encryptionRoundKeys[key + 3]);
        return result;
    }

    /// Decrypt one block using the expanded key.
    /// @param input The 16 ciphertext bytes. The input is not modified.
    /// @return The corresponding 16-byte plaintext block.
    Block decryptBlock(const Block& input) const
    {
        Block state = input;
        addRoundKey(state, rounds);
        for (unsigned round = rounds - 1; round > 0; --round)
        {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);
        return state;
    }

private:
    /// Multiply one byte by x in the AES finite field GF(2^8).
    /// @param value Polynomial coefficient to multiply by x.
    /// @return The field product reduced by the AES polynomial x^8+x^4+x^3+x+1.
    static constexpr uint8_t xtime(uint8_t value)
    {
        return static_cast<uint8_t>((value << 1U) ^ ((value >> 7U) * 0x1bU));
    }

    /// Multiply two bytes in the AES finite field GF(2^8).
    /// @param a First polynomial coefficient.
    /// @param b Second polynomial coefficient.
    /// @return The field product reduced by the AES polynomial x^8+x^4+x^3+x+1.
    static uint8_t multiply(uint8_t a, uint8_t b)
    {
        uint8_t result = 0;
        for (unsigned i = 0; i < 8; ++i)
        {
            if (b & 1U)
                result ^= a;
            const bool high = (a & 0x80U) != 0;
            a <<= 1U;
            if (high)
                a ^= 0x1bU;
            b >>= 1U;
        }
        return result;
    }

    /// Load four bytes as a portable big-endian 32-bit integer.
    /// @param bytes Pointer to at least four source bytes.
    /// @return The decoded unsigned integer.
    static uint32_t get32(const uint8_t *bytes)
    {
        return (static_cast<uint32_t>(bytes[0]) << 24U)
             | (static_cast<uint32_t>(bytes[1]) << 16U)
             | (static_cast<uint32_t>(bytes[2]) << 8U)
             | static_cast<uint32_t>(bytes[3]);
    }

    /// Store a 32-bit integer in big-endian byte order.
    /// @param block Destination AES block.
    /// @param offset First destination byte; callers use 0, 4, 8, or 12.
    /// @param value Integer to store.
    static void put32(Block& block, size_t offset, uint32_t value)
    {
        block[offset] = static_cast<uint8_t>(value >> 24U);
        block[offset + 1] = static_cast<uint8_t>(value >> 16U);
        block[offset + 2] = static_cast<uint8_t>(value >> 8U);
        block[offset + 3] = static_cast<uint8_t>(value);
    }

    /// Apply SubBytes, ShiftRows, and MixColumns to one state column.
    /// @param a State word providing the first row byte.
    /// @param b State word providing the second row byte.
    /// @param c State word providing the third row byte.
    /// @param d State word providing the fourth row byte.
    /// @return One transformed column before round-key addition.
    static uint32_t encryptColumn(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        return encryptionTables[0][a >> 24U]
             ^ encryptionTables[1][(b >> 16U) & 0xffU]
             ^ encryptionTables[2][(c >> 8U) & 0xffU]
             ^ encryptionTables[3][d & 0xffU];
    }

    /// Apply the final SubBytes and ShiftRows transformations to one column.
    /// @param a State word providing the first row byte.
    /// @param b State word providing the second row byte.
    /// @param c State word providing the third row byte.
    /// @param d State word providing the fourth row byte.
    /// @return One final transformed column before round-key addition.
    static uint32_t finalEncryptColumn(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        return (static_cast<uint32_t>(sbox[a >> 24U]) << 24U)
             | (static_cast<uint32_t>(sbox[(b >> 16U) & 0xffU]) << 16U)
             | (static_cast<uint32_t>(sbox[(c >> 8U) & 0xffU]) << 8U)
             | static_cast<uint32_t>(sbox[d & 0xffU]);
    }

    /// Expand the original cipher key into one key for every AES round.
    /// @param key The fixed-size key to expand.
    /// The generated bytes are stored in roundKeys in encryption-round order.
    void expandKey(const Key& key)
    {
        std::copy(key.begin(), key.end(), roundKeys.begin());
        size_t generated = keySize;
        unsigned rconIndex = 1;
        std::array<uint8_t, 4> word{};
        while (generated < roundKeys.size())
        {
            std::copy_n(roundKeys.begin() + static_cast<ptrdiff_t>(generated - 4), 4, word.begin());
            if ((generated % keySize) == 0)
            {
                const uint8_t first = word[0];
                word[0] = sbox[word[1]];
                word[1] = sbox[word[2]];
                word[2] = sbox[word[3]];
                word[3] = sbox[first];
                word[0] ^= rcon[rconIndex++];
            }
            else if constexpr (KeyBits == 256)
            {
                if ((generated % keySize) == 16)
                    for (uint8_t& byte: word)
                        byte = sbox[byte];
            }
            for (uint8_t byte: word)
            {
                roundKeys[generated] = roundKeys[generated - keySize] ^ byte;
                ++generated;
            }
        }
        for (size_t i = 0; i < encryptionRoundKeys.size(); ++i)
            encryptionRoundKeys[i] = get32(roundKeys.data() + 4 * i);
    }

    /// XOR one expanded round key into the cipher state.
    /// @param state The column-major AES state to modify in place.
    /// @param round Round-key index in the inclusive range [0, rounds].
    void addRoundKey(Block& state, unsigned round) const
    {
        for (size_t i = 0; i < blockSize; ++i)
            state[i] ^= roundKeys[round * blockSize + i];
    }

    /// Apply the inverse AES S-box independently to every byte.
    /// @param state AES state modified in place.
    static void invSubBytes(Block& state) { for (uint8_t& byte: state) byte = invSbox[byte]; }

    /// Undo shiftRows by rotating each row of the state to the right.
    /// @param s AES state modified in place.
    static void invShiftRows(Block& s)
    {
        const Block t = s;
        for (size_t row = 0; row < 4; ++row)
            for (size_t col = 0; col < 4; ++col)
                s[4 * col + row] = t[4 * ((col + 4 - row) & 3U) + row];
    }

    /// Apply the inverse AES linear transformation to each column.
    /// @param s AES state modified in place.
    static void invMixColumns(Block& s)
    {
        for (size_t col = 0; col < 4; ++col)
        {
            const size_t i = 4 * col;
            const uint8_t a = s[i], b = s[i + 1], c = s[i + 2], d = s[i + 3];
            s[i] = multiply(a, 14) ^ multiply(b, 11) ^ multiply(c, 13) ^ multiply(d, 9);
            s[i + 1] = multiply(a, 9) ^ multiply(b, 14) ^ multiply(c, 11) ^ multiply(d, 13);
            s[i + 2] = multiply(a, 13) ^ multiply(b, 9) ^ multiply(c, 14) ^ multiply(d, 11);
            s[i + 3] = multiply(a, 11) ^ multiply(b, 13) ^ multiply(c, 9) ^ multiply(d, 14);
        }
    }

    /// Forward byte-substitution table defined by FIPS 197.
    static constexpr std::array<uint8_t, 256> sbox = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

    /// Combined SubBytes and MixColumns tables for the four column rows.
    static constexpr std::array<std::array<uint32_t, 256>, 4> encryptionTables = [] {
        std::array<std::array<uint32_t, 256>, 4> tables{};
        for (size_t i = 0; i < tables[0].size(); ++i)
        {
            const uint8_t substituted = sbox[i];
            const uint8_t doubled = xtime(substituted);
            const uint8_t tripled = doubled ^ substituted;
            const uint32_t value = (static_cast<uint32_t>(doubled) << 24U)
                                 | (static_cast<uint32_t>(substituted) << 16U)
                                 | (static_cast<uint32_t>(substituted) << 8U)
                                 | tripled;
            tables[0][i] = value;
            tables[1][i] = std::rotr(value, 8);
            tables[2][i] = std::rotr(value, 16);
            tables[3][i] = std::rotr(value, 24);
        }
        return tables;
    }();

    /// Inverse byte-substitution table used during decryption.
    static constexpr std::array<uint8_t, 256> invSbox = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

    /// Round constants indexed from one by the AES key expansion.
    static constexpr std::array<uint8_t, 15> rcon = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d};

    /// Expanded key bytes, containing the initial key and every round key.
    std::array<uint8_t, blockSize * (rounds + 1)> roundKeys{};

    /// Expanded encryption round keys packed as portable big-endian words.
    std::array<uint32_t, 4 * (rounds + 1)> encryptionRoundKeys{};
};

/// Convenient name for AES with a 128-bit key.
using Aes128 = Aes<128>;

/// Convenient name for AES with a 256-bit key.
using Aes256 = Aes<256>;
