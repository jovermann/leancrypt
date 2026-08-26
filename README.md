# leancrypt
leancrypt is a lean, header-only C++ crypto library.

The goal is to have a single readable and portable self-contained header file per crypto primitive, without any external dependencies.
The code is pure C++ without using any nonportable builtin functions or inline assembler.

## Supported functionality

Encryption:

* AES-128 and AES-256 block encryption and decryption (FIPS 197)
* AES-128-GCM and AES-256-GCM authenticated encryption (NIST SP 800-38D)

The AES implementation is very simple and 100% portable C++. It deliberately avoids platform-specific hardware acceleration and therefore has rather low performance compared with optimized AES libraries. Its focus is readability and portability.

`Aes.hpp` provides the raw 16-byte block cipher. For application data, prefer `AesGcm.hpp`, use a unique nonce for every encryption with a given key, and transmit its authentication tag with the ciphertext. Decryption authenticates before returning plaintext.

## Why AES-GCM?

AES-GCM is an authenticated encryption mode: it provides both confidentiality and integrity. Encryption produces ciphertext together with an authentication tag. During decryption, the tag verifies that the ciphertext, nonce, and associated data have not been modified and that the correct key was used. This implementation does not return plaintext unless that verification succeeds.

Traditional encryption modes such as CBC and CTR provide confidentiality but no authentication on their own. An attacker may be able to modify their ciphertext without the receiver detecting it unless a separate message authentication scheme is added and combined correctly. GCM integrates both operations in one standard construction, avoids padding, and can also authenticate unencrypted associated data such as protocol headers.

Every encryption with a given key must use a unique nonce. A 12-byte nonce is recommended. Reusing a nonce with the same key breaks GCM's security; the nonce does not need to be secret and is normally stored or transmitted alongside the ciphertext and tag.

## Hashes

* SHA-3/224/256/384/512 hashes
    * SHA-3/128 nonstandard hash (faster than using SHA-3/224 when only needing a 128-bit hash)
* SHA-512 hash
* SHA-256 hash
* SHA-1 hash
* MD5 hash

## Performance

Focus is on readability and portability and not on performance.
While the performance is not horrible, leancrypt should not be used for data-heavy tasks.

Run all benchmarks, or select benchmark names with an fnmatch pattern:

    ./leancrypt -b
    ./leancrypt -B 'Aes*'
    ./leancrypt -B 'Hash*'

`-B` implies `-b`. Quote patterns so that the shell does not expand them before passing them to leancrypt.

Performance on a MacBook M1 Pro:

    Aes<128>    : 113.2 MB/s
    Aes<256>    : 84.1 MB/s
    AesGcm<128> : 58.5 MB/s
    AesGcm<256> : 49.6 MB/s
    HashSha3_128: 691.2 MB/s (268435456 bytes in 0.370s)
    HashSha3_224: 599.2 MB/s (268435456 bytes in 0.427s)
    HashSha3_256: 561.8 MB/s (268435456 bytes in 0.456s)
    HashSha3_384: 435.1 MB/s (268435456 bytes in 0.588s)
    HashSha3_512: 303.5 MB/s (268435456 bytes in 0.844s)
    HashSha512  : 468.8 MB/s (268435456 bytes in 0.546s)
    HashSha256  : 294.2 MB/s (268435456 bytes in 0.870s)
    HashSha1    : 459.3 MB/s (268435456 bytes in 0.557s)
    HashMd5     : 655.4 MB/s (268435456 bytes in 0.391s)
