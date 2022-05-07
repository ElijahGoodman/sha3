/* 
 * sha3_ec.h
 * 2022 Copyright © by Elijah Coleman
 */

#ifndef SHA3_EC_H_
#define SHA3_EC_H_

//----- INCLUDES -----
#include <vector>
#include <string>

#include <iostream>

//----- DEFINES -----
#define MAX_HASH_SIZE (524280ULL)	// Max digest size in bits (2^16 - 1 bytes)

//-----------------------------------------------------------------------------
namespace chash
{
	//----- TYPES ALIASES -----
	typedef unsigned long long 	int_t;
	typedef unsigned long long 	size_t;
	typedef unsigned char 		byte;
	using vec_iter = std::vector<int_t>::const_iterator;

	// --- Print State ---		// for debugging
	void print_state(const int_t state[25], const std::string& title)
	{
		std::cout << title;
		std::cout << std::setfill('0');
		for(int y = 0; y < 5; y++) {
			for (int x = 0; x < 5; x++) {
				std::cout << std::dec << "[" << x << ", " << y << "] = "
					<< std::hex  << std::nouppercase
					<< std::setw(sizeof(int_t) * 2) << state[x + y*5] << '\n';
			}
		}
		std::cout << "-------------------\n" << std::dec;
	}

	// --- Print State ---		// for debugging
	void print_state_raw(const byte state[25*sizeof(int_t)], const std::string& title)
	{
		std::cout << title << std::hex;

		for(int i = 0; i < 25*sizeof(int_t); i++) {
			std::cout << std::setw(2) << std::setfill('0') << std::uppercase
					  << int(state[i]) << ' ';
			if (!((i + 1) % 16))
				std::cout << '\n';
		}
		std::cout << "\n-------------------\n" << std::dec;
	}

	// --- Print vector<int> in hexadecimal form ---		// for debugging
	void print_data_raw(const std::vector<int_t>& data, const std::string& title)
	{
		std::cout << title << std::hex;
		for(const int_t number : data ) {
			for(int i = 0; i < sizeof(int_t); i++) {
				int temp = (number >> (i*8)) & 0xFF;
				std::cout << std::setw(2) << std::setfill('0') << std::uppercase
					   << temp << " ";
			}
		}
		std::cout << "\n-------------------\n" << std::dec;
	}

	// --- Print vector ---		// for debugging
	void print_vector(const std::vector<int_t>& data, const std::string& title)
	{
		std::cout << title;
		std::cout << std::setfill('0');
		int i=0;
		for(int_t word : data) {
			std::cout << std::dec << std::setw(3) << i << ' ' << std::hex
					  << std::uppercase << std::setfill('0')
					  << std::setw(sizeof(int_t) * 2) << word << '\n';
			i++;
		}
		std::cout << "-------------------\n" << std::dec;
	}

	//----- CONSTANTS -----
	const int_t kSHA3_domain = 0b110;
	const int_t kSHAKE_domain = 0b11111;

	static const int_t k8Bits = 8;

	static const size_t kStateSize = 25;
	static const size_t kKeccakWidth = 1600;	// in bits
	static const size_t kRounds = 24;
	static const size_t kDefaultCapacity = 512;	// in bits
	static const size_t kLaneSize = 64;			// lane size in bits

	static const size_t kRhoOffset[25] = {		// offsets for RHO step mapping
		 0,  1, 62, 28, 27,
		36, 44,  6, 55, 20,
	     3, 10, 43, 25, 39,
		41, 45, 15, 21,  8,
	  	18,  2, 61, 56, 14
	};

	static const int_t kPiJmp[24] = {	// for PI step mapping
		1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18,
		17, 11, 7, 10
	};

	static const int_t kIotaRc[24] = { // round constants for IOTA step mapping
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
		0x8000000080008000,	0x000000000000808B,	0x0000000080000001,
		0x8000000080008081, 0x8000000000008009,	0x000000000000008A,
		0x0000000000000088,	0x0000000080008009,	0x000000008000000A,
		0x000000008000808B,	0x800000000000008B,	0x8000000000008089,
		0x8000000000008003,	0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A,	0x8000000080008081,
		0x8000000000008080,	0x0000000080000001, 0x8000000080008008
	};

	//----- STRUCTURES & CLASSES -----
	template<size_t digest_size = 256, size_t capacity = kDefaultCapacity, 
			 int_t domain = kSHA3_domain>
	class Keccak	// Basic class of KECCAK algorithm
	{
	public:
		//-----------------------------
		Keccak(const Keccak&) = delete;		// copy/move constructors in undef
		Keccak(const Keccak&&) = delete;
		Keccak& operator=(Keccak&) = delete; // copy/move assignment is undef
		Keccak& operator=(Keccak&&) = delete;

		//---------------
		explicit Keccak()
		{	// Requirements: <digest_size> - in bytes, <capacity> - in bytes
			digest_size_ = digest_size % MAX_HASH_SIZE;
			if (0 <= capacity and capacity <= kKeccakWidth)
				capacity_ = capacity;
			else
				capacity_ = kDefaultCapacity;
			rate_ = kKeccakWidth - capacity_;
			rounds_ = kRounds;
			domain_ = domain;
			if (kSHA3_domain == domain)
				suf_len_ = 2;
			else if (kSHAKE_domain == domain)
				suf_len_ = 4;
		}	// end Keccak()

		//-----------
		~Keccak() {};

		// ----- Main Interface ------
		std::vector<byte> get_digest(const char* msg, const size_t len_in_bits)
		{	// Return the digest of <msg>
			// The caller ensures that the <msg> is available and valid
			// 0. Preparing 
			//		in PAD(10*1) obligatory add "11", i.e. two bits
			size_t total_len = len_in_bits + suf_len_ + 2;
			total_len += rate_ - (total_len % rate_);
			reset_state();
			// 1. Absorbing
			const byte* cur = reinterpret_cast<const byte*>(msg);
			size_t absorbed = 0;
			for (int i = 0; i < total_len/rate_; i++) {
				size_t block_size = std::min(len_in_bits - absorbed, rate_);
				size_t offset = (block_size % k8Bits) ? (block_size/k8Bits + 1)
													  : (block_size/k8Bits);
				absorb(cur, cur+offset, block_size);
				cur += offset;
				absorbed += rate_;
			}
			// 2. Squeezing and return
			return (squeeze());
		} // end MD()
		//----------------------------------------------------
		std::vector<byte> get_digest(const std::string& msg, 
									 const size_t len_in_bits)
		{	// Return the digest of <msg>
			return get_digest(msg.c_str(), len_in_bits);
		} // end MD()

	protected:
		//----- Basic KECCAK functions -----
		inline void reset_state() noexcept
		{
			for(int i=0; i < 25; i++)
				st_[i] = 0;
		}

		//----------------------
		void keccap_p() noexcept
		{	// Underlying KECCAK permutation
			for(size_t rc = 0; rc < kRounds; rc++) {
				// THETA
				int_t sheet[5] = {0};
				for (int x = 0; x < 5; x++) {	// traverse throught sheets
					sheet[x] ^= st_[x]^st_[x+5]^st_[x+10]^st_[x+15]^st_[x+20];
				}
				for (int x = 0; x < 5; x++) {
					for (int y = 0; y < 5; y++) {
						st_[x + y*5] ^= sheet[(x+4)%5] ^ rotl(sheet[(x+1)%5],1);
					}
				}
				// RHO & PI
				int_t lane1 = rotl(st_[1], kRhoOffset[1]);
				for(int i = 0; i < 23; i++) {
					st_[kPiJmp[i]] = rotl(st_[kPiJmp[i+1]], 
										  kRhoOffset[kPiJmp[i+1]]);
				}
				st_[kPiJmp[23]] = lane1;
				// CHI
				for(int y = 0; y < 25; y += 5) {	// traverse through rows
					sheet[0] = st_[y];
					sheet[1] = st_[y+1];
					for(int x = 0; x < 3; x++) {
						st_[y+x] ^= (~st_[y+(x+1)]) & st_[y+(x+2)];
					}
					st_[y+3] ^= (~st_[y+4]) & sheet[0];
					st_[y+4] ^= (~sheet[0]) & sheet[1];
				}
				// IOTA
				st_[0] ^= kIotaRc[rc];
			}
		} // end keccak_p()

		//----------------------------------------------------------
		void absorb(const byte *start, const byte *end, size_t size)
		{	// Absorbing part of input [start, end] with State array
			for (const byte* cur = start; cur != end; cur++) {
				st_raw_[cur - start] ^= *cur;
			}
			if (size < rate_) {			// domain separation and padding
				int_t cur_byte = size / k8Bits;
				int_t cur_bit = size % k8Bits;
				st_raw_[cur_byte] ^= domain_ << cur_bit;
				int overflow = (cur_bit + suf_len_ + 1) - k8Bits;
				if (overflow > 0) {	// suffix appending over 64 bit boundary
					st_raw_[cur_byte+1] ^= domain_>> (suf_len_ + 1 - overflow);
				}
				// add last byte of padding
				st_raw_[(rate_ / k8Bits) - 1] ^= 0x80;
			}
			//print_state(st, "State:\n");
			//print_state_raw(st_raw, "State (raw):\n");
			keccap_p();
		} // end absorbing()

		//----------------------------------
		std::vector<byte> squeeze() noexcept
		{	// Squeezing's part of the "sponge" construction.
			// Getting the message digest (hash)
			std::vector<byte> digest(digest_size_ / k8Bits, 0);
			size_t squeezed = 0;
			for(size_t i = 0; i < (digest_size_/rate_ + 1); i++) {
				size_t block_size = std::min((digest_size_ - squeezed), rate_);
				for(size_t j = squeezed; j < squeezed + block_size; j+=k8Bits)
					digest[j/k8Bits] = st_raw_[(j - squeezed)/k8Bits];
				squeezed += block_size;
				if(squeezed < digest_size_)
					keccap_p();
			}
			return(digest);
		} // end squeeze()

	protected:
		//-----Auxiliary functions-----
		inline int_t rotl(int_t n, size_t offset) noexcept
		{	// left-rotating the value of <n> by <offset> positions
			// If C++20 is used may be replaced by "std::rotl"
			return((n << offset) | (n >> (sizeof(n)*k8Bits - offset)));
		}

	protected:		// Class Data Members
		union {
			int_t st_[kStateSize];						// State (5 * 5 * w)
			byte  st_raw_[kStateSize * sizeof(int_t)];	// State as byte array
		};

		size_t digest_size_;
		size_t capacity_;
		size_t rate_;
		size_t rounds_;
		int_t  domain_;		// '0b10' for SHA3, '0b1111' for SHAKE
		size_t suf_len_;	// length in bits of the domain suffix
	};  // end class "Keccak"

} // end namespace "chash"

//-----------------------------------------------------------------------------
#endif /* SHA3_EC_H_ */
