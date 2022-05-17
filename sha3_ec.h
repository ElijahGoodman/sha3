/* 
 * sha3_ec.h
 * 2022 Copyright © by Elijah Coleman
 */

#ifndef SHA3_EC_H_
#define SHA3_EC_H_

//-----------------------------------------------------------------------------

#include <vector>
#include <string>
#include <iostream>
#include <iomanip>

namespace chash     // "cryptographic hash"
{
//------ TYPES ALIASES ------
typedef unsigned long long 	int_t;
typedef unsigned long long 	size_t;
typedef unsigned char 		byte;

//------ ENUMS & CONSTANTS ------
enum DigestSize : size_t {
    kD_128 = 128, kD_224 = 224, kD_256 = 256, kD_384 = 384, kD_512 = 512,
    kD_max = 524280ULL      // Max digest size in bits (2^16 - 1 bytes)
};
enum Capacity: size_t {
    kC_256 = 256, kC_448 = 448, kC_512 = 512, kC_768 = 768, kC_1024 = 1024
};
enum Domain : int_t {
    kSHA3 = 0b110, kSHAKE = 0b11111
};

static const int_t k8Bits = 8;
static constexpr int_t kIntSize = sizeof(int_t);

static_assert(8==kIntSize, "Type 'long long int' must been at least 8 bytes!");

static const size_t kStateSize = 25;
static const size_t kKeccakWidth = 1600;    // in bits
static const size_t kRounds = 24;
static const size_t kLaneSize = 64;         // lane size in bits

static const size_t kRhoOffset[kStateSize] = {  // offsets for RHO step mapping
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static const int_t kPiJmp[kStateSize-1] = {     // for PI step mapping
    1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18,
    17, 11, 7, 10
};

static const int_t kIotaRc[kRounds] = {// round constants for IOTA step mapping
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

//------ Helper Functions (Inline only) ------
inline int_t rotl(int_t n, size_t offset) noexcept
{	// left-rotating the value of <n> by <offset> positions
    // If C++20 is used may be replaced by "std::rotl"
    return((n << offset) | (n >> (sizeof(n) * k8Bits - offset)));
}

//====== Basic class of SHA3 specification ======
template<DigestSize hash_size, Capacity c, Domain dom>
class Keccak
{
public:
    Keccak(const Keccak&) = delete;     // copy/move constructors in undef
    Keccak(const Keccak&&) = delete;
    Keccak& operator=(Keccak&) = delete; // copy/move assignment is undef
    Keccak& operator=(Keccak&&) = delete;

    explicit Keccak();
    ~Keccak() {};

    //------ Main Interface ------
    std::vector<byte> get_digest(const std::string& msg, size_t len_in_bits)
                                     noexcept;  // wrapper function
    bool set_digest_size(const size_t digest_size_in_bits) noexcept;
    std::string get_hash_type() noexcept;

protected:
    std::vector<byte> get_digest(const char* msg, const size_t len_in_bits);

    //------ Basic KECCAK functions ------
    inline void reset_state() noexcept {
        for (size_t i = 0; i < kStateSize; i++)
            st_[i] = 0;
    }
    void keccap_p() noexcept;
    std::vector<byte> squeeze() noexcept;

private:
    void absorb(const byte* start, const byte* end, size_t size) noexcept;

    //------ Class Data Members ------
protected:
    union {
        int_t st_[kStateSize];                      // State (5 * 5 * w)
        byte  st_raw_[kStateSize * sizeof(int_t)];  // State as byte array
    };
    size_t digest_size_;
    size_t capacity_;
    size_t rate_;
    size_t rounds_;
    int_t  domain_;		// domain separation suffix
    size_t suf_len_;	// length in bits of the suffix
};  // end for class "Keccak" declaration

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
Keccak<hash_size, c, dom>::Keccak()
:   digest_size_(hash_size),
    capacity_(c),
    rounds_(kRounds),
    domain_(dom)
{
    rate_ = kKeccakWidth - capacity_;
    if (kSHA3 == dom)
        suf_len_ = 2;
    else if (kSHAKE == dom)
        suf_len_ = 4;
} // end Keccak()

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
std::vector<byte> Keccak<hash_size, c, dom>::get_digest(const std::string& msg,
                                                   size_t len_in_bits) noexcept
{   // Wrapper function. Return the digest of <msg>
    // WARNING: if "len_in_bits" exceeds a length of "msg",
    //          "len_in_bits" truncated by length of "msg.
    if(len_in_bits > msg.length()*k8Bits)
        len_in_bits = msg.length() * k8Bits;
    return (get_digest(msg.c_str(), len_in_bits));
} // end get_digest()

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
bool Keccak<hash_size, c, dom>::set_digest_size(const size_t hash_size_in_bits)
                                                noexcept
{   // (!) For SHAKE functions ONLY, has no effect for SHA3 functions.
    // WARNING: digest size is limited by kD_max (max hash size)
    if (kSHAKE == domain_) {
        digest_size_ = hash_size_in_bits % kD_max;
        return (true);
    }
    else
        return (false);
} // end set_digest_size()

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
std::string Keccak<hash_size, c, dom>::get_hash_type() noexcept
{   // return the type of hash function, i.e. "SHA3-224", "SHA3-256"...
    std::string hash_type = (kSHA3==domain_) ? "SHA3-" : "SHAKE";
    hash_type += std::to_string(capacity_/2);
    return (hash_type);
}

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
std::vector<byte>
Keccak<hash_size,c,dom>::get_digest(const char* msg, const size_t len_in_bits)
{   // Return the digest of <msg>
    // The caller must guarantee that the <msg> is available and valid
    // 0. Preparing
    //      in PAD(10*1) obligatory add "11", i.e. two bits
    size_t total_len = len_in_bits + suf_len_ + 2;
    total_len += rate_ - (total_len % rate_);
    reset_state();
    // 1. Absorbing
    const byte* cur = reinterpret_cast<const byte*>(msg);
    size_t absorbed = 0;
    for (size_t i = 0; i < total_len / rate_; i++) {
        size_t block_size = std::min(len_in_bits - absorbed, rate_);
        size_t offset = (block_size % k8Bits) ? (block_size/k8Bits + 1)
                                              : (block_size/k8Bits);
        absorb(cur, cur + offset, block_size);
        cur += offset;
        absorbed += rate_;
    }
    // 2. Squeezing and return
    return (squeeze());
} // end get_digest(const char* msg,...)

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
void Keccak<hash_size, c, dom>::keccap_p() noexcept
{   // Underlying KECCAK permutation
    for (size_t rc = 0; rc < kRounds; rc++) {
        // THETA
        int_t sht[5] = {0};             // "sheet"
        for (int x = 0; x < 5; x++) {   // traverse through sheets
            sht[x] ^= st_[x] ^ st_[x+5] ^ st_[x+10] ^ st_[x+15] ^ st_[x+20];
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                st_[x + y*5] ^= sht[(x + 4)%5] ^ rotl(sht[(x + 1) % 5], 1);
            }
        }
        // RHO & PI
        int_t lane1 = rotl(st_[1], kRhoOffset[1]);
        for (size_t i = 0; i < kStateSize-2; i++) {
            st_[kPiJmp[i]] = rotl(st_[kPiJmp[i + 1]],
                kRhoOffset[kPiJmp[i + 1]]);
        }
        st_[kPiJmp[23]] = lane1;
        // CHI
        for (size_t y = 0; y < kStateSize; y += 5) {   // traverse through rows
            sht[0] = st_[y];
            sht[1] = st_[y + 1];
            for (int x = 0; x < 3; x++) {
                st_[y + x] ^= (~st_[y + (x + 1)]) & st_[y + (x + 2)];
            }
            st_[y + 3] ^= (~st_[y + 4]) & sht[0];
            st_[y + 4] ^= (~sht[0]) & sht[1];
        }
        // IOTA
        st_[0] ^= kIotaRc[rc];
    } // end for(size_t rc...)
} // end keccak_p()

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
void Keccak<hash_size, c, dom>::absorb(const byte* start, const byte* end,
                                       size_t size) noexcept
{   // Absorbing part of input [start, end] with State array
    for (const byte* cur = start; cur != end; cur++) {
        st_raw_[cur - start] ^= *cur;
    }
    if (size < rate_) {         // domain separation and padding
        size_t cur_byte = size / k8Bits;
        size_t cur_bit = size % k8Bits;
        st_raw_[cur_byte] ^= domain_ << cur_bit;
        int overflow = (cur_bit + suf_len_ + 1) - k8Bits;
        if (overflow > 0) { // suffix appending over 64 bit boundary
            st_raw_[cur_byte+1] ^= domain_ >> (suf_len_ + 1 -overflow);
        }
        // add last byte of padding
        st_raw_[(rate_ / k8Bits) - 1] ^= 0x80;
    }
    keccap_p();
} // end absorb()

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
std::vector<byte> Keccak<hash_size, c, dom>::squeeze() noexcept
{   // Squeezing's part of the "sponge" construction.
    // Getting the message digest (hash)
    size_t rem = digest_size_ % k8Bits;
    std::vector<byte> digest(digest_size_/k8Bits + (rem ? 1 : 0), 0);
    size_t squeezed = 0;
    for (size_t i = 0; i < (digest_size_/rate_ + 1); i++) {
        size_t block_size = std::min((digest_size_ - squeezed), rate_);
        for (size_t j = squeezed; j < squeezed + block_size; j += k8Bits)
            digest[j / k8Bits] = st_raw_[(j - squeezed)/k8Bits];
        squeezed += block_size;
        if (squeezed < digest_size_)
            keccap_p();
    }
    // If digest size in bits not multiple by 8
    if(rem)
        digest[digest.size() - 1] &= 0xFF >> (k8Bits - rem);
    return(digest);
} // end squeeze()
//====== end for class "Keccak" definition ======


//====== Enhanced class of SHA3 specification ======
// Application of the IUF concept (Init/Update/Finalize)
template<DigestSize hash_size, Capacity c, Domain dom>
class IUFKeccak : public Keccak<hash_size, c, dom>
{   // The class is designed to process input messages with a length
    // multiple of 8 (i.e. byte-oriented messages)
    using str_const_iter = std::string::const_iterator;
public:
    IUFKeccak(const IUFKeccak&) = delete;    // copy/move constructors in undef
    IUFKeccak(const IUFKeccak&&) = delete;
    IUFKeccak& operator=(IUFKeccak&) = delete; // copy/move assignment is undef
    IUFKeccak& operator=(IUFKeccak&&) = delete;

    explicit IUFKeccak()
    : rate_in_bytes_(this->rate_ / k8Bits)  {  init();  }
    ~IUFKeccak() {}

    //------ Main Interface ------
    void init() noexcept;
    size_t update(const str_const_iter start, const str_const_iter end);
    size_t update(const std::string& data); // wrapper function
    std::vector<byte> finalize() noexcept;

private:		// Class Data Members
    size_t rate_in_bytes_;
    size_t byte_absorbed_;
    char   separator_;
}; // end for class IUFKeccak declaration

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
void IUFKeccak<hash_size, c, dom>::init() noexcept
{
    byte_absorbed_ = 0;
    this->reset_state();
} // end init()

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
size_t IUFKeccak<hash_size, c, dom>::update(const str_const_iter start, 
                                            const str_const_iter end)
{   // Update State based on input data
    if (start >= end)
        return (0);
    const size_t len = end - start;
    size_t left_to_process = len;
    size_t block_size = std::min(len, rate_in_bytes_ - byte_absorbed_);
    str_const_iter block = start;

    while (left_to_process) {
        for (str_const_iter cur = block; cur != block + block_size; cur++) {
            this->st_raw_[byte_absorbed_ + (cur - block)] ^= *cur;
        }
        byte_absorbed_ += block_size;
        if (byte_absorbed_ == rate_in_bytes_) {
            this->keccap_p();
            byte_absorbed_ = 0;
        }
        left_to_process -= block_size;
        if (left_to_process) {
            block += block_size;
            block_size = std::min(left_to_process, rate_in_bytes_);
        }
    } // end while(left_to_process)

    return (len);
} // end update()

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
size_t IUFKeccak<hash_size, c, dom>::update(const std::string& data)
{   // Wrapper function
    return (update(data.begin(), data.end()));
}

//----------------------------------------------------
template<DigestSize hash_size, Capacity c, Domain dom>
std::vector<byte> IUFKeccak<hash_size, c, dom>::finalize() noexcept
{   // Add domain separation and padding, return digest
    this->st_raw_[byte_absorbed_ % rate_in_bytes_] ^= this->domain_;
    this->st_raw_[rate_in_bytes_ - 1] ^= 0x80;

    this->keccap_p();       // Last permutation

    return(this->squeeze());
} // end finalize()
//====== end for class IUFKeccak definition ======


//------ Predefined Aliases ------
using SHA3_224 = Keccak<kD_224, kC_448, kSHA3>;     // SHA3
using SHA3_256 = Keccak<kD_256, kC_512, kSHA3>;
using SHA3_384 = Keccak<kD_384, kC_768, kSHA3>;
using SHA3_512 = Keccak<kD_512, kC_1024, kSHA3>;
using SHAKE128 = Keccak<kD_128, kC_256, kSHAKE>;    // SHAKE
using SHAKE256 = Keccak<kD_256, kC_512, kSHAKE>;

using SHA3_224_IUF = IUFKeccak<kD_224, kC_448, kSHA3>;  // SHA3 (IUF concept)
using SHA3_256_IUF = IUFKeccak<kD_256, kC_512, kSHA3>;
using SHA3_384_IUF = IUFKeccak<kD_384, kC_768, kSHA3>;
using SHA3_512_IUF = IUFKeccak<kD_512, kC_1024, kSHA3>;
using SHAKE128_IUF = IUFKeccak<kD_128, kC_256, kSHAKE>; // SHAKE (IUF concept)
using SHAKE256_IUF = IUFKeccak<kD_256, kC_512, kSHAKE>;

} // end namespace "chash"

//-----------------------------------------------------------------------------
#endif /* SHA3_EC_H_ */
