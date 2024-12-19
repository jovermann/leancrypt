# leancrypt
leancrypt is a lean, header-only C++ crypto library.

Currently only some hashes are supported.

The goal is to have a single readable and portable self-contained header file per crypto primitive, without any external dependencies.
The code is pure C++ without using any nonportable builtin functions or inline assembler.

## Supported functionality

Hashes:

* SHA-3/224/256/384/512 hashes
    * SHA-3/128 nonstandard hash (faster than using SHA-3/224 when only needing a 128-bit hash)
* SHA-512 hash
* SHA-256 hash
* SHA-1 hash
* MD5 hash

## Performance

Focus is on readability and portability and not on performance.
While the performance is not horrible, leancrypt should not be used for data-heavy tasks.

Performance on a MacBook M1 Pro:

    HashSha3_128: 691.2 MB/s (268435456 bytes in 0.370s)
    HashSha3_224: 599.2 MB/s (268435456 bytes in 0.427s)
    HashSha3_256: 561.8 MB/s (268435456 bytes in 0.456s)
    HashSha3_384: 435.1 MB/s (268435456 bytes in 0.588s)
    HashSha3_512: 303.5 MB/s (268435456 bytes in 0.844s)
    HashSha512  : 468.8 MB/s (268435456 bytes in 0.546s)
    HashSha256  : 294.2 MB/s (268435456 bytes in 0.870s)
    HashSha1    : 459.3 MB/s (268435456 bytes in 0.557s)
    HashMd5     : 655.4 MB/s (268435456 bytes in 0.391s)
