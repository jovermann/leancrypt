// bench - Test program for crypto functions.
//
// Copyright (c) 2024 Johannes Overmann
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

#include "HashSha512.hpp"
#include "refSha512.hpp"
#include "HashSha256.hpp"
#include "refSha256.hpp"
#include "HashSha1.hpp"
#include "refSha1.hpp"
#include "Hash.hpp"

#include "MiscUtils.hpp"
#include "CommandLineParser.hpp"
#include <exception>
#include <iomanip>


/// Command line options.
static unsigned verbose = 0;


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

    // Test adding individual bytes of data.
    HashClass hasher;
    for (size_t i = 0; i < input.length(); i++)
    {
        updateHash(hasher, input.substr(i, 1));
    }
    errors += checkHash("single-char", hexReferenceHash, ut1::hexlify(hasher.finalize()), ut1::typeName<HashClass>(), input);

    return errors;
}

/// Test a list of reference values.
/// Each hash is for the input "a"* i where i is in range [0..size_of_ref-1].
template<class HashClass>
unsigned testRefList(const char *hashes[])
{
    /// Global error state.
    unsigned errors = 0;
    for (size_t i = 0; hashes[i] && (i < 10); i++)
    {
        errors += testHash<HashClass>(std::string(i, 'a'), hashes[i]);
    }
    if (errors)
    {
        std::cout << std::left << std::setw(10) << ut1::typeName<HashClass>() << ": " << std::dec << errors << " error(s) found\n";
    }
    else
    {
        std::cout << std::left << std::setw(10) << ut1::typeName<HashClass>() << ": ok\n";
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
    std::cout << std::left << std::setw(10) << ut1::typeName<HashClass>() << ": " << std::fixed << std::dec << std::setprecision(1) << std::setw(6) << rate / 1024.0 / 1024.0 << "MB/s (" << size << " bytes in " << std::setprecision(3) << elapsed << "s)\n";
    if (verbose >= 2)
    {
        std::cout << ut1::hexlify(hash) << "\n";
    }
}

/// Run tests.
void runTests()
{
    unsigned errors = 0;
    errors += testRefList<HashSha512>(refSha512);
    errors += testRefList<HashSha256>(refSha256);
    errors += testRefList<HashSha1>(refSha1);
    std::cout << std::dec << errors << " error(s) found total\n";
}

/// Run benchmarks.
void runBenchmarks(size_t size)
{
    runBench<HashSha512>(size);
    runBench<HashSha256>(size);
    runBench<HashSha1>(size);
}

/// Main.
int main(int argc, const char *argv[])
{
        // Command line options.
    ut1::CommandLineParser cl("bench",  "Run benchmarks and tests of the leancrypt crypto functions.\n"
                                           "\n"
                                           "Usage: $programName [OPTIONS]\n"
                                           "\n"
                                           "Run all tests and benchmarks:\n"
                                           "> $programName\n"
                                           "\n"
                                           "Add --test and/or --benchmark to run only the tests and or benchmarks, respectively.\n"
                                           "\n",
        "\n"
        "$programName version $version *** Copyright (c) 2024 Johannes Overmann *** https://github.com/jovermann/leancrypt",
        "0.0.2");

    cl.addHeader("\nOptions:\n");
    cl.addOption('t', "test", "Run tests (e.g. check functions against reference data).");
    cl.addOption('b', "benchmark", "Run benchmarks.");
    cl.addOption('s', "size", "Data size for benchmarks in MBytes.", "SIZE", "256");
    cl.addOption('v', "verbose", "Increase verbosity. Specify multiple times to be more verbose.");

    // Parse command line options.
    cl.parse(argc, argv);
    verbose = cl.getCount("verbose");

    // Run everything by default.
    if (!(cl("test") || cl("benchmark")))
    {
        cl.setValue("test");
        cl.setValue("benchmark");
    }

    try
    {
        if (cl("test"))
        {
            runTests();
        }
        if (cl("benchmark"))
        {
            runBenchmarks(cl.getUInt("size") << 20);
        }
    }
    catch (const std::exception& e)
    {
        cl.error(e.what());
    }

    return 0;
}
