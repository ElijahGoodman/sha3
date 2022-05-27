# **Simple implementation of SHA3 hash algorithm**

This simple C++ single-header implementation of the SHA-3 algorithm is based on FIPS 202
[SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](https://github.com)

## Language features and tools

This implementation has been developed and tested with:
 * ISO C++14 and higher.
 * GCC compiler (v10.3.0) / MSVC++ 14.28 (Visual Studio 2019).

Next IDEs was used:
 * Eclipse CPP (for Windows, using MinGW64).
 * MS Visual Studio 2019. 

## Overview

In order to use this implementation in your project, include the header file
`sha3_ec.h`. The specified file defines the namespace `chash` which includes
two classes `Keccak` and `IUF_Keccak`.  For convenience and clarity, the 
following aliases are used:

    SHA3
    SHA3_IUF

The first one (`SHA3`) is the base class, which provides a simple set of
functions for getting a digest (hash) of a message. 
The second class - `SHA3_IUF` - inherits from the base class and extends
the functionality by adding additional functions, in particular, it provides
the ability to use the IUF (Init/Update/Finalize) scheme to absorb input data
part by part.


**This is bold text**

*This text is italicized*

~~This was mistaken text~~

**This text is _extremely_ important**

***All this text is important***

Some code example (cpp-syntax)

```cpp
#inlcude <iostream>

int main(int, char**) {
    std::cout << "Hello, World!\n";
    return 0;
}
```
