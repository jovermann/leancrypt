// bench - Test program for crypto functions.
//
// Copyright (c) 2024 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#include "HashSha3.hpp"
#include "refSha3_224.hpp"
#include "refSha3_256.hpp"
#include "refSha3_384.hpp"
#include "refSha3_512.hpp"
#include "HashSha512.hpp"
#include "refSha512.hpp"
#include "HashSha256.hpp"
#include "refSha256.hpp"
#include "HashSha1.hpp"
#include "refSha1.hpp"
#include "HashMd5.hpp"
#include "refMd5.hpp"
#include "Hash.hpp"
#include "Aes.hpp"
#include "AesGcm.hpp"

#include "MiscUtils.hpp"
#include "CommandLineParser.hpp"
#include <exception>
#include <iomanip>
#include <array>
#include <cassert>
#include <stdexcept>

/// Maximum hash name len to align output.
static const int hashNameLen = 12;

/// Command line options.
static unsigned verbose = 0;

static void require(bool condition, const char *message)
{
    if (!condition)
        throw std::runtime_error(message);
}

static std::vector<uint8_t> fromHex(std::string_view hex)
{
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        return static_cast<uint8_t>(c - 'A' + 10);
    };
    assert((hex.size() & 1U) == 0);
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>((digit(hex[2 * i]) << 4U) | digit(hex[2 * i + 1]));
    return bytes;
}

template<size_t N>
static std::array<uint8_t, N> arrayFromHex(std::string_view hex)
{
    const auto bytes = fromHex(hex);
    assert(bytes.size() == N);
    std::array<uint8_t, N> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

/// Set benchmark verbosity.
void setBenchVerbose(unsigned verbose_)
{
    verbose = verbose_;
}

/// Print error.
static unsigned checkHash(const std::string& testName, const std::string& expectedHash, const std::string& actualHash, const std::string_view& hashName, const std::string& input)
{
    if (expectedHash == actualHash)
    {
        return 0;
    }

    std::cout << "FAILED: " << testName << ": " << hashName << ":";
    std::cout << " exp=\"" << expectedHash << "\"";
    std::cout << " act=\"" << actualHash << "\"";
    std::cout << " len=" << input.length();
//    std::cout << " inp=\"" << input << "\"";
    std::cout << "\n";
    return 1;
}

/// Test a single hash value.
template<class HashClass>
unsigned testHash(const std::string& input, const std::string& hexReferenceHash)
{
    unsigned errors = 0;

    // Test adding whole input at once.
    errors += checkHash("all", hexReferenceHash, ut1::hexlify(calcHash<HashClass>(input)), ut1::typeName<HashClass>(), input);

#if 1
    // Test adding individual bytes of data.
    HashClass hasher;
    for (size_t i = 0; i < input.length(); i++)
    {
        updateHash(hasher, input.substr(i, 1));
    }
    errors += checkHash("single-char", hexReferenceHash, ut1::hexlify(hasher.finalize()), ut1::typeName<HashClass>(), input);
#endif

    return errors;
}

/// Test a list of reference values.
/// Each hash is for the input "a"* i where i is in range [0..size_of_ref-1].
template<class HashClass>
unsigned testRefList(const char *hashes[])
{
    /// Global error state.
    unsigned errors = 0;
    for (size_t i = 0; hashes[i]; i++)
    {
        errors += testHash<HashClass>(std::string(i, 'a'), hashes[i]);
    }
    if (errors)
    {
        std::cout << std::left << std::setw(hashNameLen) << ut1::typeName<HashClass>() << ": " << std::dec << errors << " error(s) found\n";
    }
    else
    {
        std::cout << std::left << std::setw(hashNameLen) << ut1::typeName<HashClass>() << ": ok\n";
    }
    return errors;
}

/// Run benchmark on a specific hasher.
template<class HashClass>
void runBench(size_t size)
{
    std::string data(size, 'a');
    double start = ut1::getTimeSec();
    std::vector<uint8_t> hash = calcHash<HashClass>(data);
    double elapsed = ut1::getTimeSec() - start;
    double rate = size / elapsed;
    std::cout << std::left << std::setw(hashNameLen) << ut1::typeName<HashClass>() << ": " << std::fixed << std::dec << std::setprecision(1) << std::setw(6) << rate / 1024.0 / 1024.0 << "MB/s (" << size << " bytes in " << std::setprecision(3) << elapsed << "s)\n";
    if (verbose >= 2)
    {
        std::cout << ut1::hexlify(hash) << "\n";
    }
}

template<class Cipher>
void runAesBench(size_t size)
{
    typename Cipher::Key key{};
    typename Cipher::Block block{};
    const Cipher cipher(key);
    const double start = ut1::getTimeSec();
    for (size_t offset = 0; offset < size; offset += Cipher::blockSize)
        block = cipher.encryptBlock(block);
    const double elapsed = ut1::getTimeSec() - start;
    std::cout << std::left << std::setw(hashNameLen) << ut1::typeName<Cipher>() << ": "
              << std::fixed << std::dec << std::setprecision(1) << std::setw(6)
              << size / elapsed / 1024.0 / 1024.0 << "MB/s (" << size << " bytes in "
              << std::setprecision(3) << elapsed << "s)\n";
    if (verbose >= 2) std::cout << ut1::hexlify(std::vector<uint8_t>(block.begin(), block.end())) << "\n";
}

template<class Gcm>
void runGcmBench(size_t size)
{
    typename Gcm::Key key{};
    const std::array<uint8_t, 12> nonce{};
    const std::vector<uint8_t> data(size);
    const Gcm gcm(key);
    const double start = ut1::getTimeSec();
    const auto encrypted = gcm.encrypt(nonce, data);
    const double elapsed = ut1::getTimeSec() - start;
    std::cout << std::left << std::setw(hashNameLen) << ut1::typeName<Gcm>() << ": "
              << std::fixed << std::dec << std::setprecision(1) << std::setw(6)
              << size / elapsed / 1024.0 / 1024.0 << "MB/s (" << size << " bytes in "
              << std::setprecision(3) << elapsed << "s)\n";
    if (verbose >= 2) std::cout << ut1::hexlify(std::vector<uint8_t>(encrypted.tag.begin(), encrypted.tag.end())) << "\n";
}

static void testAes()
{
    const auto plaintext = arrayFromHex<16>("00112233445566778899aabbccddeeff");
    const Aes128 aes128(arrayFromHex<16>("000102030405060708090a0b0c0d0e0f"));
    const auto encrypted128 = aes128.encryptBlock(plaintext);
    require(encrypted128 == arrayFromHex<16>("69c4e0d86a7b0430d8cdb78070b4c55a"), "AES-128 encryption test failed");
    require(aes128.decryptBlock(encrypted128) == plaintext, "AES-128 decryption test failed");

    const Aes256 aes256(arrayFromHex<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    const auto encrypted256 = aes256.encryptBlock(plaintext);
    require(encrypted256 == arrayFromHex<16>("8ea2b7ca516745bfeafc49904b496089"), "AES-256 encryption test failed");
    require(aes256.decryptBlock(encrypted256) == plaintext, "AES-256 decryption test failed");
    std::cout << std::left << std::setw(hashNameLen) << "AES-128/256" << ": ok\n";
}

static void testGcm()
{
    const std::array<uint8_t, 12> nonce{};
    const std::vector<uint8_t> zeros(16);
    const Aes128Gcm gcm128(Aes128Gcm::Key{});
    const auto encrypted128 = gcm128.encrypt(nonce, zeros);
    require(encrypted128.ciphertext == fromHex("0388dace60b6a392f328c2b971b2fe78"), "AES-128-GCM ciphertext test failed");
    require(encrypted128.tag == arrayFromHex<16>("ab6e47d42cec13bdf53a67b21257bddf"), "AES-128-GCM tag test failed");

    std::vector<uint8_t> decrypted;
    require(gcm128.decrypt(nonce, encrypted128.ciphertext, encrypted128.tag, decrypted), "AES-GCM decryption rejected a valid tag");
    require(decrypted == zeros, "AES-GCM decryption test failed");
    auto badTag = encrypted128.tag;
    badTag[0] ^= 1;
    decrypted = {42};
    require(!gcm128.decrypt(nonce, encrypted128.ciphertext, badTag, decrypted), "AES-GCM accepted an invalid tag");
    require(decrypted == std::vector<uint8_t>{42}, "AES-GCM exposed unauthenticated plaintext");

    const Aes256Gcm gcm256(Aes256Gcm::Key{});
    const auto encrypted256 = gcm256.encrypt(nonce, zeros);
    require(encrypted256.ciphertext == fromHex("cea7403d4d606b6e074ec5d3baf39d18"), "AES-256-GCM ciphertext test failed");
    require(encrypted256.tag == arrayFromHex<16>("d0d1c8a799996bf0265b98b5d48ab919"), "AES-256-GCM tag test failed");

    const Aes128Gcm longGcm(arrayFromHex<16>("feffe9928665731c6d6a8f9467308308"));
    const auto aad = fromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const auto plain = fromHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    const auto longResult = longGcm.encrypt(fromHex("cafebabefacedbad"), plain, aad);
    require(longResult.ciphertext == fromHex("61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598"), "AES-GCM non-96-bit nonce ciphertext test failed");
    require(longResult.tag == arrayFromHex<16>("3612d2e79e3b0785561be14aaca2fccb"), "AES-GCM non-96-bit nonce tag test failed");
    std::cout << std::left << std::setw(hashNameLen) << "AES-GCM" << ": ok\n";
}

/// Run tests.
void runTests()
{
    unsigned errors = 0;
    testAes();
    testGcm();
    errors += testRefList<HashSha3_224>(refSha3_224);
    errors += testRefList<HashSha3_256>(refSha3_256);
    errors += testRefList<HashSha3_384>(refSha3_384);
    errors += testRefList<HashSha3_512>(refSha3_512);
    errors += testRefList<HashSha512>(refSha512);
    errors += testRefList<HashSha256>(refSha256);
    errors += testRefList<HashSha1>(refSha1);
    errors += testRefList<HashMd5>(refMd5);
    std::cout << std::dec << errors << " error(s) found total\n";
}

/// Run benchmarks.
void runBenchmarks(size_t size)
{
    // AES is slower than the hashes, so process 1/16 of the requested size.
    const size_t aesSize = size / 16;
    runAesBench<Aes128>(aesSize);
    runAesBench<Aes256>(aesSize);
    runGcmBench<Aes128Gcm>(aesSize);
    runGcmBench<Aes256Gcm>(aesSize);
    runBench<HashSha3_128>(size);
    runBench<HashSha3_224>(size);
    runBench<HashSha3_256>(size);
    runBench<HashSha3_384>(size);
    runBench<HashSha3_512>(size);
    runBench<HashSha512>(size);
    runBench<HashSha256>(size);
    runBench<HashSha1>(size);
    runBench<HashMd5>(size);
}
