/******************************************************************************

Copyright (c) 2022 Elijah Coleman

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

******************************************************************************/

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

//------ STRUCTS / ENUMS / CONSTANTS ------
enum class HashSize {
    kD_128 = 128, kD_224 = 224, kD_256 = 256, kD_384 = 384, kD_512 = 512,
    kD_max = 524280      // Max digest size in bits (2^16 - 1 bytes)
};
enum class Domain : int_t {
    kDomSHA3 = 0b110, kDomSHAKE = 0b11111
};

struct KeccParam {   // KECCAK parameters
    explicit KeccParam()        // default - SHA3-256
    :   hash_size(HashSize::kD_256), dom(Domain::kDomSHA3)
    {}
    explicit KeccParam(chash::HashSize hs, chash::Domain d)
    :   hash_size(hs), dom(d)
    {}
    KeccParam& operator=(KeccParam other)
    {
        this->hash_size = other.hash_size;
        this->dom = other.dom;
        return (*this);
    }
public:
    chash::HashSize     hash_size;
    chash::Domain       dom;
};

const KeccParam kSHA3_224{HashSize::kD_224, Domain::kDomSHA3};
const KeccParam kSHA3_256{HashSize::kD_256, Domain::kDomSHA3};
const KeccParam kSHA3_384{HashSize::kD_384, Domain::kDomSHA3};
const KeccParam kSHA3_512{HashSize::kD_512, Domain::kDomSHA3};
const KeccParam kSHAKE128(HashSize::kD_128, Domain::kDomSHAKE);
const KeccParam kSHAKE256(HashSize::kD_256, Domain::kDomSHAKE);

static const int_t k8Bits = 8;
static constexpr int_t kIntSize = sizeof(int_t);

static_assert(8==kIntSize, "Type 'long long int' must been 8 bytes!");

static const int    kStateSize = 25;
static const size_t kKeccakWidth = 1600;    // in bits
static const int    kRounds = 24;
static const size_t kLaneSize = 64;         // lane size in bits
static const int_t  kIntMax = 0xFFFFFFFFFFFFFFFFULL;

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
class Keccak
{
public:
    Keccak(const Keccak&) = delete;     // copy/move constructors in undef
    Keccak(const Keccak&&) = delete;
    Keccak& operator=(Keccak&) = delete; // copy/move assignment is undef
    Keccak& operator=(Keccak&&) = delete;

    explicit Keccak(KeccParam param) {  setup(param);  }
    Keccak() {  setup(kSHA3_256);  }     // by default SHA3-256
    ~Keccak() {};

    //------ Main Interface ------
    virtual void setup(const KeccParam &param);
    std::vector<byte> get_digest(const char* msg, const size_t len_in_bits);
    std::vector<byte> get_digest(const std::string& msg, size_t len_in_bits)
                                     noexcept;  // wrapper function
    void get_digest(std::string &msg, std::string &digest) noexcept;
    bool set_digest_size(const size_t digest_size_in_bits) noexcept;
    std::string get_hash_type() noexcept;
    size_t get_rate() const {  return (rate_); }

protected:
    //------ Basic KECCAK functions ------
    inline void reset_state() noexcept {
        for (int i = 0; i < kStateSize; i++)
            st_[i] = 0;
    }
    void keccak_p() noexcept;
    std::vector<byte> squeeze() noexcept;
    void squeeze(std::string& digest) noexcept;

private:
    inline void absorb(const char* msg, const size_t len_in_bits) noexcept;

    //------ Class Data Members ------
protected:
    union {
        int_t st_[kStateSize];                      // State (5 * 5 * w)
        byte  st_raw_[kStateSize * sizeof(int_t)];  // State as byte array
    };
    size_t hash_size_;  // in bits
    size_t capacity_;   // in bits
    size_t rate_;       // in bits
    int_t  domain_;		// domain separation suffix
    size_t suf_len_;	// length in bits of the suffix
};  // end for class "Keccak" declaration

//----------------------------------------
void Keccak::setup(const KeccParam &param)
{
    hash_size_ = static_cast<size_t>(param.hash_size);
    capacity_ = hash_size_ * 2;
    domain_ = static_cast<int_t>(param.dom);
    rate_ = kKeccakWidth - capacity_;
    if (Domain::kDomSHA3 == param.dom)
        suf_len_ = 2;
    else if (Domain::kDomSHAKE == param.dom)
        suf_len_ = 4;
} // end setup(...)

//-----------------------------------------------------------------------------
std::vector<byte> Keccak::get_digest(const char* msg, const size_t len_in_bits)
{   // Return the digest of <msg>
    if (!msg)
        return (std::vector<byte>());
    // 1. Absorbing
    absorb(msg, len_in_bits);
    // 2. Squeezing and return
    return (squeeze());
} // end get_digest(const char* msg,...)

//----------------------------------------------------------
std::vector<byte> Keccak::get_digest(const std::string& msg,
                                     size_t len_in_bits) noexcept
{   // Wrapper function. Return the digest of <msg>
    // WARNING: if "len_in_bits" exceeds a length of "msg",
    //          "len_in_bits" truncated by length of "msg.
    if(len_in_bits > msg.length()*k8Bits)
        len_in_bits = msg.length() * k8Bits;
    return (get_digest(msg.c_str(), len_in_bits));
} // end get_digest(...)

//---------------------------------------------------------------------
void Keccak::get_digest(std::string &msg, std::string &digest) noexcept
{
    // 1. Absorbing
    absorb(msg.c_str(), msg.length() * k8Bits);
    // 2. Squeezing
    squeeze(digest);
    return;
} // end get_digest(...)

//-------------------------------------------------------------------
bool Keccak::set_digest_size(const size_t hash_size_in_bits) noexcept
{   // (!) For SHAKE functions ONLY, has no effect for SHA3 functions.
    // WARNING: digest size is limited by kD_max (max hash size)
    if (static_cast<int_t>(Domain::kDomSHAKE) == domain_) {
        hash_size_ = hash_size_in_bits % static_cast<size_t>(HashSize::kD_max);
        return (true);
    }
    else
        return (false);
} // end set_digest_size(...)

//------------------------------------------
std::string Keccak::get_hash_type() noexcept
{   // return the type of hash function, i.e. "SHA3-224", "SHA3-256"...
    std::string hash_type = 
        (static_cast<int_t>(Domain::kDomSHA3)==domain_) ? "SHA3-" : "SHAKE";
    hash_type += std::to_string(capacity_/2);
    return (hash_type);
}

//------------------------------
void Keccak::keccak_p() noexcept
{   // Underlying KECCAK permutation
    for (int rc = 0; rc < kRounds; rc++) {
        // THETA
        int_t sht_l[5];             // "sheet"
        int_t sht_r[5];
        for (int x = 0; x < 5; x++) {    // traverse through sheets
            sht_l[x] = st_[x]^st_[x+5]^st_[x+10]^st_[x+15]^st_[x+20];
            sht_r[x] = rotl(sht_l[x],1);
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++)
                st_[x + y*5] ^= sht_l[(x+4)%5] ^ sht_r[(x+1) % 5];
        }
        // RHO & PI
        int_t lane1 = rotl(st_[1], kRhoOffset[1]);
        for (int i = 0; i < kStateSize-2; i++)
            st_[kPiJmp[i]] = rotl(st_[kPiJmp[i+1]], kRhoOffset[kPiJmp[i+1]]);
        st_[kPiJmp[23]] = lane1;
        // CHI
        for (int y = 0; y < kStateSize; y += 5) {   // traverse through rows
            sht_l[0] = st_[y];
            sht_l[1] = st_[y+1];
            for (int x = 0; x < 3; x++) {
                //st_[y+x] ^= (~st_[y+(x+1)]) & st_[y+(x+2)];
                st_[y+x] ^= (st_[y+(x+1)] ^ kIntMax) & st_[y+(x+2)];
            }
            st_[y+3] ^= (~st_[y+4]) & sht_l[0];
            st_[y+4] ^= (~sht_l[0]) & sht_l[1];
        }
        // IOTA
        st_[0] ^= kIotaRc[rc];
    } // end for(size_t rc...)
} // end keccak_p()

//---------------------------------------------------------------------
void Keccak::absorb(const char* msg, const size_t len_in_bits) noexcept
{
    // Preparing
    const size_t rate8 = rate_ / k8Bits;
    //      in PAD(10*1) obligatory add "11", i.e. two bits
    size_t total_len = len_in_bits + suf_len_ + 2;
    total_len += (total_len % rate_) ? (rate_ - total_len % rate_) : 0;
    //      let's deal with domain separation and padding
    const size_t dom_byte = (len_in_bits / k8Bits);
    const size_t dom_bit = len_in_bits % k8Bits;
    const size_t dom_step = len_in_bits / rate_;
    const int over = static_cast<int>(dom_bit + suf_len_ + 1 - k8Bits);
    int dom_over_step = -1;
    if (over > 0)      // suffix appending over 64 bit boundary
        dom_over_step = static_cast<int>((len_in_bits + suf_len_ + 1) / rate_);
    reset_state();
    // Absorbing
    const byte* cur = reinterpret_cast<const byte*>(msg);
    size_t absorbed(0), block(0), offset(0);
    for (size_t n(total_len / rate_), i(0); i < n; i++) {
        block = std::min(len_in_bits - absorbed, rate_);
        cur += offset;
        offset = (block % k8Bits) ? (block / k8Bits + 1) : (block / k8Bits);
        //absorb(cur, cur + offset);   // absorb but not padding
        if (offset % (rate_ / k8Bits) == 0) {
            const int_t* start = reinterpret_cast<const int_t*>(cur);
            for (int i = 0; i < offset / kIntSize; i++)
                st_[i] ^= *(start + i);
        }
        else {
            for (const byte* start = cur; start != (cur + offset); start++)
                st_raw_[start - cur] ^= *start;
        }
        absorbed += block;
        if (dom_step == i)
            st_raw_[dom_byte % rate8] ^= domain_ << dom_bit;
        if (dom_over_step == i)
            st_raw_[(dom_byte + 1) % rate8] ^= domain_ >> (suf_len_ + 1 - over);
        if (i == (n - 1))
            st_raw_[rate8 - 1] ^= 0x80;  // add last byte of padding
        keccak_p();
    }
} // end absorb(...)

//------------------------------------------
std::vector<byte> Keccak::squeeze() noexcept
{   // Squeezing's part of the "sponge" construction.
    // Getting the message digest (hash)
    size_t rem = hash_size_ % k8Bits;
    std::vector<byte> digest(hash_size_ / k8Bits + (rem ? 1 : 0), 0);
    size_t squeezed = 0;
    for (size_t i = 0; i < (hash_size_ / rate_ + 1); i++) {
        size_t block_size = std::min((hash_size_ - squeezed), rate_);
        if (block_size == rate_) {
            int_t* cur = reinterpret_cast<int_t*>(digest.data()) + squeezed / k8Bits;
            for (int i = 0; i < rate_ / kLaneSize; i++, cur++)
                *cur = st_[i];
        }
        else {
            for (size_t j = squeezed; j < squeezed + block_size; j += k8Bits)
                digest[j / k8Bits] = st_raw_[(j - squeezed) / k8Bits];
        }
        squeezed += block_size;
        if (squeezed < hash_size_)
            keccak_p();
    }
    // If digest size in bits not multiple by 8
    if (rem)
        digest[digest.size() - 1] &= 0xFF >> (k8Bits - rem);
    return(digest);
} // end squeeze()

//------------------------------------------------
void Keccak::squeeze(std::string& digest) noexcept
{
    size_t rem = hash_size_ % k8Bits;
    digest.resize(hash_size_/k8Bits + (rem ? 1 : 0), 0);
    size_t squeezed = 0;
    for (size_t i = 0; i < (hash_size_/rate_ + 1); i++) {
        size_t block_size = std::min((hash_size_ - squeezed), rate_);
        for (size_t j = squeezed; j < squeezed + block_size; j += k8Bits)
            digest[j / k8Bits] = st_raw_[(j - squeezed)/k8Bits];
        squeezed += block_size;
        if (squeezed < hash_size_)
            keccak_p();
    }
    if (rem)       // If digest size in bits not multiple by 8
        digest[digest.size() - 1] &= 0xFF >> (k8Bits - rem);
    return;
} // end squeeze()
//====== end for class "Keccak" definition ======


//====== Enhanced class of SHA3 specification ======
// Application of the IUF concept (Init/Update/Finalize)
class IUFKeccak : public Keccak
{   // The class is designed to process input messages with a length
    // multiple of 8 (i.e. byte-oriented messages)
    using str_const_iter = std::string::const_iterator;
public:
    IUFKeccak(const IUFKeccak&) = delete;    // copy/move constructors in undef
    IUFKeccak(const IUFKeccak&&) = delete;
    IUFKeccak& operator=(IUFKeccak&) = delete; // copy/move assignment is undef
    IUFKeccak& operator=(IUFKeccak&&) = delete;

    explicit IUFKeccak(KeccParam param)
    :   Keccak(param), rate_in_bytes_(this->rate_ / k8Bits), separator_(0)
    {  init();  }
    IUFKeccak()
    :   Keccak(kSHA3_256), rate_in_bytes_(this->rate_ / k8Bits), separator_(0)
    {  init();  }
    ~IUFKeccak() {}

    //------ Main Interface ------
    virtual void setup(const KeccParam& param) override;
    void init() noexcept;
    size_t update(const char* data, const size_t size); // WARNING: UNSAFE!!!
    size_t update_fast(const char* data, const size_t size);
    std::vector<byte> finalize() noexcept;

    // Wrapper functions
    size_t update(const str_const_iter start, const str_const_iter end);
    size_t update(const std::string& data);

    // Utility functions
    void set_separator(const char sep) noexcept   {  separator_ = sep;  }
    friend std::ostream& operator<<(std::ostream& out, chash::IUFKeccak& obj);

private:		// Class Data Members
    size_t rate_in_bytes_;
    size_t byte_absorbed_;
    char   separator_;
}; // end for class IUFKeccak declaration

//-------------------------------------------
void IUFKeccak::setup(const KeccParam& param)
{
    Keccak::setup(param);
    rate_in_bytes_ = rate_ / k8Bits;
} // end IUFKeccak::setup(...)

//-----------------------------
void IUFKeccak::init() noexcept
{
    byte_absorbed_ = 0;
    this->reset_state();
} // end init()

//----------------------------------------------------------------------------
size_t IUFKeccak::update(const str_const_iter start, const str_const_iter end)
{   // Update State based on input data
    return (update(&(*start), end - start));
} // end update()

//-----------------------------------------------
size_t IUFKeccak::update(const std::string& data)
{   // Wrapper function
    return (update(&data.front(), data.length()));
}

//-----------------------------------------------------------
size_t IUFKeccak::update_fast(const char* data, const size_t size)
{   // Some optimization for loading data into State
    size_t rate_in_8byte = rate_in_bytes_ / kIntSize; // rate as array of int_t
    size_t left_to_process = size;

    // For the case when the data block is absorbed by the state starting
    // from st_[0] (i.e. byte_absorbed_ == 0), and the block size is equal
    // to the rate: we absorb by 8 bytes at once (as an 8 byte integer)
    if(!byte_absorbed_ and (left_to_process/rate_in_8byte)) {
        const int_t* block = reinterpret_cast<const int_t*>(data);
        while(left_to_process > rate_in_bytes_) {
            for(size_t i = 0; i < rate_in_8byte; i++)
                st_[i] ^= block[i];
            block += rate_in_8byte;
            left_to_process -= rate_in_bytes_;
            this->keccak_p();
        }
    }
    // The remaining bytes are absorbed in a simple way (byte by byte)
    return (update(data + (size - left_to_process), left_to_process));
} // end IUFKeccak::update_fast()

//-----------------------------------------------------------
size_t IUFKeccak::update(const char* data, const size_t size)
{   // WARNING: UNSAFE function (raw pointer 'data', memory control needed)!!!
    // Update State based on input data
    if (nullptr == data)
        return (0);
    size_t left_to_process = size;
    size_t block_size = std::min(left_to_process, rate_in_bytes_-byte_absorbed_);
    const char* block = data;

    while (left_to_process) {
        for (const char* cur = block; cur != block + block_size; cur++) {
            this->st_raw_[byte_absorbed_ + (cur - block)] ^= *cur;
        }
        byte_absorbed_ += block_size;
        if (byte_absorbed_ == rate_in_bytes_) {
            this->keccak_p();
            byte_absorbed_ = 0;
        }
        left_to_process -= block_size;
        if (left_to_process) {
            block += block_size;
            block_size = std::min(left_to_process, rate_in_bytes_);
        }
    } // end while(left_to_process)
    return (size);
} // end update(...)

//----------------------------------------------
std::vector<byte> IUFKeccak::finalize() noexcept
{   // Add domain separation and padding, return digest
    this->st_raw_[byte_absorbed_ % rate_in_bytes_] ^= this->domain_;
    this->st_raw_[rate_in_bytes_ - 1] ^= 0x80;

    this->keccak_p();       // Last permutation

    return(this->squeeze());
} // end finalize()

//------ Overload output for IUFKeccak ------
std::ostream& operator<<(std::ostream& out, chash::IUFKeccak& obj)
{
    std::vector<chash::byte> digest = obj.finalize();
    char prev_fill = out.fill('0');
    out << std::hex;
    for(size_t i = 0; i < digest.size(); i++) {
        out << std::setw(2) << static_cast<int>(digest[i]);
        if(obj.separator_ and (i+1 != digest.size()))
            out << obj.separator_;
    }
    out.fill(prev_fill);
    out << std::flush << std::dec;
    return (out);
} // end

//====== end for class IUFKeccak definition ======

//------ TYPES ALIASES ------
using SHA3 = Keccak;
using SHA3_IUF = IUFKeccak;
using SHA3Param = KeccParam;

} // end namespace "chash"

//-----------------------------------------------------------------------------
#endif /* SHA3_EC_H_ */
