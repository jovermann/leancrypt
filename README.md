# leancrypt
leancrypt is a lean, header-only C++ crypto library.

Currently only some hashes are supported.

The goal is to have a single readable and portable self-contained header file per crypto primitive, without any external dependencies.
The code is pure C++ without using any nonportable builtin functions or inline assembler.

## Supported functionality

Hashes:

* SHA-3/224/256/384/512 hashes
* SHA-512 hash
* SHA-256 hash
* SHA-1 hash
* MD5 hash

## Performance

Focus is on readability and portability and not on performance.
While the performance is not horrible, leancrypt should not be used for data-heavy tasks.

Performance on a MacBook M1 Pro:

    HashSha3_224: 588.0 MB/s (268435456 bytes in 0.435s)
    HashSha3_256: 564.1 MB/s (268435456 bytes in 0.454s)
    HashSha3_384: 432.8 MB/s (268435456 bytes in 0.591s)
    HashSha3_512: 300.0 MB/s (268435456 bytes in 0.853s)
    HashSha512  : 322.4 MB/s (268435456 bytes in 0.794s)
    HashSha256  : 205.3 MB/s (268435456 bytes in 1.247s)
    HashSha1    : 398.8 MB/s (268435456 bytes in 0.642s)
    HashMd5     : 541.5 MB/s (268435456 bytes in 0.473s)




