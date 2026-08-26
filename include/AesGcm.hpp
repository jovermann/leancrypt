// AES-GCM authenticated encryption implementation.
//
// Copyright (c) 2026 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include "Aes.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

/// AES-GCM authenticated encryption according to NIST SP 800-38D.
/// @tparam KeyBits AES key length in bits; must be 128 or 256.
/// This is a very simple, 100% portable C++ implementation intended for
/// readability. It uses no platform-specific acceleration and consequently
/// has rather low performance compared with optimized AES-GCM implementations.
/// Each instance retains an expanded AES key. A nonce must never be reused with
/// the same key. A 12-byte nonce is recommended and takes GCM's fast path.
template<size_t KeyBits>
class AesGcm
{
public:
    /// AES block-cipher specialization underlying this GCM specialization.
    using Cipher = Aes<KeyBits>;

    /// Fixed-size key accepted by this GCM specialization.
    using Key = typename Cipher::Key;

    /// Full-size 128-bit GCM authentication tag.
    using Tag = typename Cipher::Block;

    /// Result of an authenticated encryption operation.
    struct Encrypted
    {
        /// Encrypted bytes; this has the same length as the plaintext.
        std::vector<uint8_t> ciphertext;

        /// Authentication tag covering the ciphertext, nonce, and associated data.
        Tag tag;
    };

    /// Construct an AES-GCM context and expand @p key.
    /// @param key Exactly Cipher::keySize bytes of key material.
    explicit AesGcm(const Key& key): aes(key) {}

    /// Construct an AES-GCM context from dynamically sized key material.
    /// @param key Key material, which must contain exactly Cipher::keySize bytes.
    /// @throws std::invalid_argument if @p key has the wrong size.
    explicit AesGcm(std::span<const uint8_t> key): aes(key) {}

    /// Encrypt and authenticate a complete message.
    /// @param nonce Unique nonce for this key; 12 bytes is strongly recommended.
    /// @param plaintext Message bytes to encrypt. Empty messages are supported.
    /// @param associatedData Unencrypted bytes to authenticate, such as headers.
    /// @return Ciphertext and a full 128-bit authentication tag.
    Encrypted encrypt(std::span<const uint8_t> nonce, std::span<const uint8_t> plaintext,
                      std::span<const uint8_t> associatedData = {}) const
    {
        const Tag j0 = initialCounter(nonce);
        Encrypted result{crypt(plaintext, j0), {}};
        result.tag = authenticationTag(j0, associatedData, result.ciphertext);
        return result;
    }

    /// Authenticate and decrypt a complete message.
    /// @param nonce The same nonce supplied during encryption.
    /// @param ciphertext Bytes returned by encrypt.
    /// @param tag The full authentication tag returned by encrypt.
    /// @param plaintext Destination replaced with the decrypted bytes only after
    /// authentication succeeds; it is left unchanged on failure.
    /// @param associatedData The exact unencrypted data supplied during encryption.
    /// @return true if authentication succeeded and plaintext was produced;
    /// false if the tag, nonce, ciphertext, associated data, or key did not match.
    bool decrypt(std::span<const uint8_t> nonce, std::span<const uint8_t> ciphertext,
                 const Tag& tag, std::vector<uint8_t>& plaintext,
                 std::span<const uint8_t> associatedData = {}) const
    {
        const Tag j0 = initialCounter(nonce);
        const Tag expected = authenticationTag(j0, associatedData, ciphertext);
        uint8_t difference = 0;
        for (size_t i = 0; i < expected.size(); ++i)
            difference |= expected[i] ^ tag[i];
        if (difference != 0)
            return false;
        plaintext = crypt(ciphertext, j0);
        return true;
    }

private:
    /// Increment the least-significant 32 bits of a GCM counter block.
    /// @param counter Counter block modified in place using big-endian arithmetic.
    static void incrementCounter(Tag& counter)
    {
        for (size_t i = 16; i-- > 12;)
            if (++counter[i] != 0)
                break;
    }

    /// Apply GCM's AES counter-mode transformation.
    /// @param input Plaintext when encrypting or ciphertext when decrypting.
    /// @param j0 Initial counter block derived from the nonce.
    /// @return Transformed bytes with the same length as @p input.
    /// Encryption and decryption use the same operation.
    std::vector<uint8_t> crypt(std::span<const uint8_t> input, const Tag& j0) const
    {
        std::vector<uint8_t> output(input.size());
        Tag counter = j0;
        for (size_t offset = 0; offset < input.size(); offset += 16)
        {
            incrementCounter(counter);
            const Tag stream = aes.encryptBlock(counter);
            const size_t count = std::min<size_t>(16, input.size() - offset);
            for (size_t i = 0; i < count; ++i)
                output[offset + i] = input[offset + i] ^ stream[i];
        }
        return output;
    }

    /// XOR one 128-bit value into another.
    /// @param a Left operand and in-place destination.
    /// @param b Right operand, which is not modified.
    static void xorBlock(Tag& a, const Tag& b)
    {
        for (size_t i = 0; i < 16; ++i)
            a[i] ^= b[i];
    }

    /// Load eight bytes as a portable big-endian 64-bit integer.
    /// @param block Source block.
    /// @param offset First source byte; callers use 0 or 8.
    /// @return The decoded unsigned integer.
    static uint64_t get64(const Tag& block, size_t offset)
    {
        uint64_t value = 0;
        for (size_t i = 0; i < 8; ++i)
            value = (value << 8U) | block[offset + i];
        return value;
    }

    /// Accumulate one 64-bit half of a field operand into a GHASH product.
    /// @param x Operand bits processed from most to least significant.
    /// @param zHigh Most-significant half of the product accumulator.
    /// @param zLow Least-significant half of the product accumulator.
    /// @param vHigh Most-significant half of the shifted second operand.
    /// @param vLow Least-significant half of the shifted second operand.
    static void multiplyHalf(uint64_t x, uint64_t& zHigh, uint64_t& zLow,
                             uint64_t& vHigh, uint64_t& vLow)
    {
        for (uint64_t bit = uint64_t{1} << 63U; bit != 0; bit >>= 1U)
        {
            const uint64_t selected = 0U - static_cast<uint64_t>((x & bit) != 0);
            zHigh ^= vHigh & selected;
            zLow ^= vLow & selected;

            const uint64_t reduction = 0U - (vLow & 1U);
            vLow = (vLow >> 1U) | (vHigh << 63U);
            vHigh = (vHigh >> 1U) ^ (0xe100000000000000ULL & reduction);
        }
    }

    /// Multiply two 128-bit values in GCM's binary field GF(2^128).
    /// @param x First field element in big-endian bit order.
    /// @param y Second field element in big-endian bit order.
    /// @return Field product reduced by GCM's defining polynomial.
    static Tag multiply(const Tag& x, const Tag& y)
    {
        uint64_t zHigh = 0;
        uint64_t zLow = 0;
        uint64_t vHigh = get64(y, 0);
        uint64_t vLow = get64(y, 8);
        multiplyHalf(get64(x, 0), zHigh, zLow, vHigh, vLow);
        multiplyHalf(get64(x, 8), zHigh, zLow, vHigh, vLow);

        Tag result{};
        put64(result, 0, zHigh);
        put64(result, 8, zLow);
        return result;
    }

    /// Store a 64-bit integer in big-endian byte order inside a tag-sized block.
    /// @param block Destination block modified in place.
    /// @param offset First destination byte; callers use 0 or 8.
    /// @param value Integer to store.
    static void put64(Tag& block, size_t offset, uint64_t value)
    {
        for (size_t i = 0; i < 8; ++i)
            block[offset + 7 - i] = static_cast<uint8_t>(value >> (8U * i));
    }

    /// Fold a byte sequence into an existing GHASH accumulator.
    /// @param state GHASH accumulator updated in place.
    /// @param h Hash subkey produced by encrypting the all-zero AES block.
    /// @param bytes Bytes to hash, padded with zeros to a block boundary.
    static void hashBytes(Tag& state, const Tag& h, std::span<const uint8_t> bytes)
    {
        for (size_t offset = 0; offset < bytes.size(); offset += 16)
        {
            Tag block{};
            const size_t count = std::min<size_t>(16, bytes.size() - offset);
            std::copy_n(bytes.begin() + static_cast<ptrdiff_t>(offset), count, block.begin());
            xorBlock(state, block);
            state = multiply(state, h);
        }
    }

    /// Calculate GHASH over associated data and ciphertext, including bit lengths.
    /// @param associatedData Unencrypted authenticated bytes.
    /// @param ciphertext Encrypted message bytes.
    /// @return The 128-bit GHASH result.
    Tag ghash(std::span<const uint8_t> associatedData, std::span<const uint8_t> ciphertext) const
    {
        const Tag h = aes.encryptBlock(Tag{});
        Tag state{};
        hashBytes(state, h, associatedData);
        hashBytes(state, h, ciphertext);
        Tag lengths{};
        put64(lengths, 0, static_cast<uint64_t>(associatedData.size()) * 8U);
        put64(lengths, 8, static_cast<uint64_t>(ciphertext.size()) * 8U);
        xorBlock(state, lengths);
        return multiply(state, h);
    }

    /// Derive GCM's initial counter block from a nonce.
    /// @param nonce Nonce bytes; the 12-byte form is encoded directly, while all
    /// other lengths are processed with GHASH as specified by SP 800-38D.
    /// @return The 128-bit initial counter block J0.
    Tag initialCounter(std::span<const uint8_t> nonce) const
    {
        if (nonce.size() == 12)
        {
            Tag j0{};
            std::copy(nonce.begin(), nonce.end(), j0.begin());
            j0[15] = 1;
            return j0;
        }
        return ghash({}, nonce);
    }

    /// Produce the authentication tag for one encrypted message.
    /// @param j0 Initial counter block derived from the message nonce.
    /// @param associatedData Unencrypted authenticated bytes.
    /// @param ciphertext Encrypted message bytes.
    /// @return Full 128-bit GCM tag.
    Tag authenticationTag(const Tag& j0, std::span<const uint8_t> associatedData,
                          std::span<const uint8_t> ciphertext) const
    {
        Tag tag = aes.encryptBlock(j0);
        const Tag hash = ghash(associatedData, ciphertext);
        xorBlock(tag, hash);
        return tag;
    }

    /// Expanded AES cipher key used for counter encryption and GHASH setup.
    Cipher aes;
};

/// Convenient name for AES-128-GCM.
using Aes128Gcm = AesGcm<128>;

/// Convenient name for AES-256-GCM.
using Aes256Gcm = AesGcm<256>;
