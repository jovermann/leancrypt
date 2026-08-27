// leancrypt command line tool.
//
// Copyright (c) 2026 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#include "CommandLineParser.hpp"
#include "Hash.hpp"
#include "HashMd5.hpp"
#include "HashSha1.hpp"
#include "HashSha256.hpp"
#include "HashSha3.hpp"
#include "HashSha512.hpp"
#include "MiscUtils.hpp"
#include "UnitTest.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

void runTests();
void runBenchmarks(size_t size, const std::string& pattern);
void setBenchVerbose(unsigned verbose);

namespace
{

#ifndef ENABLE_UNIT_TEST

struct Hasher
{
    std::string name;
    std::string description;
    std::function<std::vector<uint8_t>(const std::filesystem::path&)> hashFile;
};

template<class HashClass>
std::vector<uint8_t> hashFile(const std::filesystem::path& path)
{
    HashClass     hasher;
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Unable to open '" + path.string() + "' for reading.");
    }

    std::vector<char> buffer(1024 * 1024);
    while (file)
    {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0)
        {
            hasher.update(reinterpret_cast<const uint8_t*>(buffer.data()), static_cast<size_t>(bytesRead));
        }
    }
    if (!file.eof())
    {
        throw std::runtime_error("Error while reading '" + path.string() + "'.");
    }

    return hasher.finalize();
}

const std::vector<Hasher>& getHashers()
{
    static const std::vector<Hasher> hashers = {
        {"sha3-128", "SHA-3/128 (non-standard)", hashFile<HashSha3_128>},
        {"sha3-224", "SHA-3/224", hashFile<HashSha3_224>},
        {"sha3-256", "SHA-3/256", hashFile<HashSha3_256>},
        {"sha3-384", "SHA-3/384", hashFile<HashSha3_384>},
        {"sha3-512", "SHA-3/512", hashFile<HashSha3_512>},
        {"sha512", "SHA-512", hashFile<HashSha512>},
        {"sha256", "SHA-256", hashFile<HashSha256>},
        {"sha1", "SHA-1", hashFile<HashSha1>},
        {"md5", "MD5", hashFile<HashMd5>},
    };
    return hashers;
}

std::string normalizeHashName(std::string name)
{
    name = ut1::tolower(name);
    ut1::replaceStringInPlace(name, "_", "-");
    return name;
}

const Hasher* findHasher(const std::string& name)
{
    const std::string normalizedName = normalizeHashName(name);
    for (const auto& hasher: getHashers())
    {
        if (hasher.name == normalizedName)
        {
            return &hasher;
        }
    }
    return nullptr;
}

void listHashers()
{
    for (const auto& hasher: getHashers())
    {
        std::cout << hasher.name << "  " << hasher.description << "\n";
    }
}

std::vector<std::filesystem::path> getFiles(const std::vector<std::string>& args)
{
    std::vector<std::filesystem::path> files;
    for (const std::string& arg: args)
    {
        std::filesystem::path path(arg);
        if (!std::filesystem::exists(path))
        {
            throw std::runtime_error("Path '" + path.string() + "' does not exist.");
        }
        if (std::filesystem::is_regular_file(path))
        {
            files.push_back(path);
        }
        else if (std::filesystem::is_directory(path))
        {
            for (const auto& entry: std::filesystem::recursive_directory_iterator(path))
            {
                if (entry.is_regular_file())
                {
                    files.push_back(entry.path());
                }
            }
        }
        else
        {
            throw std::runtime_error("Path '" + path.string() + "' is neither a regular file nor a directory.");
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

int runCli(int argc, const char* argv[])
{
    ut1::CommandLineParser cl(
        "leancrypt",
        "Hash files and run leancrypt benchmarks.\n"
        "\n"
        "Usage: $programName [OPTIONS] FILE_OR_DIR...\n"
        "\n"
        "Hash files:\n"
        "> $programName -H sha256 src\n"
        "\n"
        "List hash algorithms:\n"
        "> $programName -H list\n"
        "\n",
        "\n"
        "$programName version $version ($compileDate) *** Copyright (c) 2026 Johannes Overmann *** https://github.com/jovermann/leancrypt",
        "0.0.3");

    cl.addHeader("\nOptions:\n");
    cl.addOption('b', "bench", "Run benchmarks.");
    cl.addOption('B', "bench-filter", "Run benchmarks matching an fnmatch pattern, for example 'Aes*' or 'Hash*'; implies --bench.", "PATTERN", "*");
    cl.addOption('H', "hash", "Hash algorithm to use, or 'list' to list algorithms.", "HASH", "sha256");
    cl.addOption('s', "size", "Data size for benchmarks in MBytes.", "SIZE", "256");
    cl.addOption('t', "test", "Run hash implementation tests.");
    cl.addOption('v', "verbose", "Increase verbosity. Specify multiple times to be more verbose.");

    cl.parse(argc, argv);
    setBenchVerbose(cl.getCount("verbose"));

    try
    {
        const std::string hashName = normalizeHashName(cl.getStr("hash"));
        if (hashName == "list")
        {
            listHashers();
            return 0;
        }

        bool didWork = false;
        if (cl("test"))
        {
            runTests();
            didWork = true;
        }
        if (cl("bench") || cl.getCount("bench-filter"))
        {
            runBenchmarks(cl.getUInt("size") << 20, cl.getStr("bench-filter"));
            didWork = true;
        }

        if (!cl.getArgs().empty())
        {
            const Hasher* hasher = findHasher(hashName);
            if (!hasher)
            {
                throw std::runtime_error("Unknown hash algorithm '" + cl.getStr("hash") + "'. Use '-H list' to list algorithms.");
            }
            for (const auto& path: getFiles(cl.getArgs()))
            {
                std::cout << ut1::hexlify(hasher->hashFile(path)) << "  " << path.string() << "\n";
            }
            didWork = true;
        }

        if (!didWork)
        {
            cl.error("No input paths specified. Use -b to run benchmarks or -H list to list hash algorithms.");
        }
    }
    catch (const std::exception& e)
    {
        cl.error(e.what());
    }

    return 0;
}

#endif

} // namespace

int main(int argc, const char* argv[])
{
#ifdef ENABLE_UNIT_TEST
    (void)argc;
    (void)argv;
    runTests();
    UnitTestRegistry::runTests();
    return 0;
#else
    return runCli(argc, argv);
#endif
}
