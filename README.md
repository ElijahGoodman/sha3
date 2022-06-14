# **Simple implementation of SHA3 hash algorithm**

This simple C++ single-header implementation of the SHA-3 algorithm is based on FIPS 202
[SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](https://csrc.nist.gov/publications/detail/fips/202/final)

Implementation works correctly on little-endian x86-64 architectures.

## Language features and tools

This implementation has been developed and tested with:
 * ISO C++14 and higher.
 * GCC (v10.3.0 and higher) / MSVC++ v14.28 and higher.
 * Tested on Windows 8.1 (x64), Windows 10 (x64)

Next IDEs was used:
 * EclipseCPP 4.20.0 (Windows, MinGW64).
 * MS Visual Studio 2019 (Version 16.11.13).

## Overview

In order to use this implementation in your project, include the header file
`sha3_ec.h`. The specified file defines the namespace `chash` which includes
two classes `Keccak` and `IUF_Keccak`.  For convenience and clarity, the
following aliases are used:
```cpp
    using SHA3 = Keccak;
    using SHA3_IUF = IUFKeccak;
    using SHA3Param = KeccParam
```
The first one - `SHA3` - is the base class, which provides a simple set of
functions for getting a digest (hash) of a message. Among other things, it
allows to get a digest of a message, the length of which is defined in bits
(bit-aligned string).
The second class - `SHA3_IUF` - inherits from the base class and extends
the functionality by appending additional functions. In particular, `SHA3_IUF`
provides the ability to use the IUF (Init/Update/Finalize) scheme to absorb
input data block by block.

Structure `SHA3Param` is used to initialize objects of
the specified classes. Instance of this class has the **SHA3-256** setup by default.
All major SHA3 & SHAKE types are predefined as global constants:
```CPP
    const SHA3Param kSHA3_224, kSHA3_256, kSHA3_384, kSHA3_512;
    const SHA3Param kSHAKE128, kSHAKE256;
```

## Using

Let's creating an object of `SHA3_IUF`, for instance setting it up to SHA3-384,
and then getting the digest of some string:
```cpp
    #include "sha3_ec.h"
    ...
    chash::SHA3_IUF obj(chash::kSHA3_384);
    std::string str = "I wanna hashing it up!";
    std::vector<chash::byte> digest = obj.get_digest(str, str.size());

    auto hash = obj.get_digest("Use first 27 bits of me", 27); // length specified in bits
```
The following example will try to get the message digest using the schema
**Init / Update / Finalize** (e.g. with one of the XOF function SHAKE128):
```cpp
    std::string str = "I wanna hashing it up";
    chash::SHA3_IUF obj;       // "Initialize" (SHA3-256 by default)
    obj.setup(chash::kSHAKE128);  // setup to SHAKE128
    obj.set_digest_size(999);  // For XOFs ONLY: set the digest length (in bits!)
    obj.update(str);                             // "Update"
    std::cout << "Digest: " << obj << std::endl; // "Finalize" included

    obj.init();                                       // Another try
    obj.set_separator(':');                           // Some setup
    obj.set_digest_size(512);                         // in bits !!!
    obj.update(str.substr(0, 8));                     // "I wanna "
    obj.update(str.begin() + 9, str.begin() + 13);    // "hash"
    obj.update(str.begin() + 13, str.end()-2);        // " it "
    const char *oops = "uuppppppp....Connection terminated!";
    obj.update(oops, std::strlen(oops));
    auto res = obj.finalize();
```

## API features

For `SHA3` class:

   virtual void setup(const KeccParam &param);
   std::vector<byte> get_digest(const char* msg, const size_t len_in_bits);
   std::vector<byte> get_digest(const std::string& msg, size_t len_in_bits)
                                    noexcept;  // wrapper function
   void get_digest(std::string &msg, std::string &digest) noexcept;
   bool set_digest_size(const size_t digest_size_in_bits) noexcept;
   std::string get_hash_type() noexcept;
   size_t get_rate() const {  return (rate_); }

  * `setup` - Setting the type of hash algorithm.
  * `get_digest(const char* msg, const size_t len_in_bits)` - Return the digest
  of the message as **vector** (length specifies in bits).
  * `get_digest(const std::string &msg, size_t len_in_bits)` - Wrapper-function.
  The message is presents as **string**.
  * `get_digest(std::string &msg, std::string &digest)` - The function calculates
  the digest of **msg** and stores result in **digest**.
  * `set_digest_size` - For XOFs only: set the length of digest (***in bits!***).
  * `get_hash_type` - Return the string like *'SHA3-256'* or *'SHAKE128'*.
  * `get_rate` - Return **rate** value (***in bits!***).

For `SHA3_IUF` class:

  * `init` - Initialize the object; current **State** is reset to zero.
  * `update` - Update **State** with new data.
  * `update_fast` - Can be used to speed up data absorption if the size of the
  data block is a multiple of the **rate**;
  * `finalize` - return digest as `std::vector<unsigned char>`;
  * `set_separator` - set byte separator (utility function for printing).
  * `operator<<` - Overloaded **operator<<** for output.

### Some notes:
  * In function `get_digest`, the transmitted length of the data block (string)
  is indicated ***in bits***, while in function `update` and `update_fast`
  it is indicated ***in bytes***.
  * In spite of functions `get_digets` and `update` being able to accept `const char*` as
  arguments, I recommend using safer wrappers function that work with `std::string`
  or `std::string::const_iterator`.
  * Function `update_fast` can speed up the absorption of the block of data by
  the **State**. To be absorbed faster, the size of the block of data must be
  a multiple of the **rate**. For example:
```cpp
    using namespace chash;  // Only for example :)

    SHA3_IUF obj(kSHA3_512);

    size_t block_size = 1024 * (obj.get_rate() / 8); // 73728 Bytes for SHA3-512
    std::string block(block_size, 0);

    get_data_from_anywhere(&block.front(), block.size());
    obj.update_fast(block.c_str(), block.size());
    std::cout << "Digest=" << obj << "\n";
```
  * The `tests/test_sha3.cpp` file is a simple test app to verify that the main
  interface works correctly.

## SHA3MD

**sha3md** is a simple console application for getting a digest of a single
message or a file. I took example from the famous applications like **openssl**
or **sha3sum**. Of course, **sha3md** works slower than the tough guys mentioned
above. For speed up it's necessary to use SIMD and intrinsics (like SSE or AVX),
and this is a completely different story.

The following example calculates SHA3-512 hash of all files in the current
directory and store result to the file `digest_of_files.txt`:

    $ ./sha3md -sha3-512 -out digest_of_files.txt &(ls)

Displaying an empty string digest:

    $ echo -n "" | ./sha3md -shake128 -len 64 -sep ":" -u
    SHAKE128(stdin)= 7F:9C:2B:A4:E8:8F:82:7D:61:60:45:50:76:05:85:3E

## CAVP Testing

File `tests/valid_sys.cpp` contains tests based on
[Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing).

## Conclusion.

I would like to hope that this implementation will be useful to someone.

Best wishes!

2022. Elijah Coleman.
