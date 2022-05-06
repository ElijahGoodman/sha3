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


//------------------------------------------------------------------------------
namespace chash
{
	//----- TYPES ALIASES -----
	typedef unsigned long long 	int_t;
	typedef unsigned long long 	size_t;
	typedef unsigned char 		byte;
	using vec_iter = std::vector<int_t>::const_iterator;

	// --- Print State ---		// for debugging
	void print_state(const int_t data[25], const std::string& title)
	{
		std::cout << title;
		std::cout << std::setfill('0');
		for(int y = 0; y < 5; y++) {
			for (int x = 0; x < 5; x++) {
				std::cout << std::dec << "[" << x << ", " << y << "] = "
					<< std::hex  << std::nouppercase
					<< std::setw(sizeof(int_t) * 2) << data[x + y*5] << '\n';
			}
		}
		std::cout << "-------------------\n" << std::dec;
	}

	// --- Print State ---		// for debugging
	void print_state_raw(const std::vector<int_t>& state, const std::string& title)
	{
		std::cout << title << std::hex;

		int i=0;
		for(int x = 0; x < 5; x++) {
			for(int y = 0; y < 5; y++) {
				int_t lane = state[x*5 + y];
				unsigned char *c = reinterpret_cast<unsigned char*>(&lane);
				for(int i = 0; i < sizeof(int_t); i++) {
					std::cout << std::setw(2) << std::setfill('0') << std::uppercase
							  << static_cast<unsigned int>(c[i]) << ' ';
				}
				if(i%2)
					std::cout << '\n';
				i++;
			}
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
	const int_t SHA3_DOMAIN = 0b110;
	const int_t SHAKE_DOMAIN = 0b11111;

	static const int_t EIGHT_BITS = 8;
	static const int_t EIGHT_BYTES = 8;
	static constexpr int_t W = sizeof(int_t) * EIGHT_BITS; 	// must been 64 :)

	const size_t MAX_HASH_SIZE = 65535;	// Max digest size in bytes
	static const size_t STATE_SIZE = 25;
	static const size_t KECCAK_WIDTH = 200;	// in bytes
	static const size_t rounds_count = 24;	// in bytes
	static const size_t DEF_CAPACITY = 64;	// in bytes

	static constexpr size_t rho_off[25] = {	// offsets for RHO step mapping
		    0,   1%W, 190%W,  28%W,  91% W,
		 36%W, 300%W,   6%W,  55%W, 276% W,
	      3%W,  10%W, 171%W, 153%W, 231% W,
		105%W,  45%W,  15%W,  21%W, 136% W,
	  	210%W,  66%W, 253%W, 120%W,  78% W
	};

	static const int_t pi_jmp[24] = {	// for PI step mapping
		1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18,
		17, 11, 7, 10
	};

	static const int_t iota_rc[24] = {	// round constants for IOTA step mapping
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
		0x8000000080008000,	0x000000000000808B,	0x0000000080000001,
		0x8000000080008081, 0x8000000000008009,	0x000000000000008A,
		0x0000000000000088,	0x0000000080008009,	0x000000008000000A,
		0x000000008000808B,	0x800000000000008B,	0x8000000000008089,
		0x8000000000008003,	0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A,	0x8000000080008081,
		0x8000000000008080,	0x0000000080000001, 0x8000000080008008
	};

	//----- TYPES & CLASSES -----
	class keccak
	{	// Basic class of KECCAK algorithm
	public:
		//----------------------------------------------------------------------
		keccak() = delete;	// default constructor is undefined
		keccak(const keccak&) = delete;		// copy/move constructors in undef
		keccak(const keccak&&) = delete;
		keccak& operator=(keccak&) = delete;	// copy/move assignment is undef
		keccak& operator=(keccak&&) = delete;

		//-----------------------------------------------------
		explicit keccak(size_t d_size, size_t cap, int_t dom = SHA3_DOMAIN)
		{	// <d_size> - in bytes, <cap> - in bytes
			digest_size = (d_size <= MAX_HASH_SIZE) ? d_size : MAX_HASH_SIZE;
			capacity = (0 <= cap and cap <= KECCAK_WIDTH) ? cap : DEF_CAPACITY;
			rate = KECCAK_WIDTH - capacity;
			rounds = rounds_count;
			domain = dom;

			if(dom == SHA3_DOMAIN)			suff_len = 2;
			else if(dom == SHAKE_DOMAIN)	suff_len = 4;

			reset_state();
		}

		//-----------
		~keccak() {};

	public: 		// Main Interface
		std::vector<byte> MD(const std::string &msg, int_t len_in_bits)
		{	// Return the message digest
			if(msg.size()*EIGHT_BITS < len_in_bits)
				len_in_bits = msg.size() * EIGHT_BITS;

			// 1. Preparing input data
			std::vector<int_t> data;
			const int_t obligatory_pad = 2;	// in PAD(10*1) obligatory add "11"

			int_t total_len = len_in_bits + suff_len + obligatory_pad;
			int_t bits_to_pad = rate*EIGHT_BITS - (total_len % (rate*EIGHT_BITS));
			total_len += bits_to_pad;

			data.reserve(total_len / W);
			data.resize(total_len / W, 0);

			for(size_t i = 0; i < msg.size(); i++) {
				size_t j = i/EIGHT_BYTES;
				data[j] |= static_cast<int_t>(0xFFULL & msg[i]) << ((i%EIGHT_BYTES)*EIGHT_BYTES);
			}

			//print_vector(data, "Input data:\n");
			//print_data_raw(data, "Input data:\n");

			// domain separation and padding
			int_t cur_lane = len_in_bits / W;
			int_t cur_bit = len_in_bits % W;
			data[cur_lane] |= domain << cur_bit;;
			// if total size > 64 bit, i.e. we have an overflow
			int overflow = (cur_bit + suff_len + 1) - W;
			if (overflow > 0) {
				data[cur_lane + 1] = domain >> (suff_len + 1 - overflow);
			}
			// add last byte of padding
			data[data.size() - 1] |= 0x8000000000000000ULL;

			//print_vector(data, "Data after padding:\n");
			//print_data_raw(data, "Data after padding:\n");


			// 2. Absorbing
			reset_state();
			absorbing(data);

			// 3. Squeezing and return
			return (squeezing());
		}

	protected:
		//----------------------------------
		//----- Basic KECCAK functions -----
		//----------------------------------
		inline void reset_state() noexcept
		{
			for(int i=0; i < 25; i++)
				st[i] = 0;
		}

		//----------------------
		void keccap_p() noexcept
		{	// Underlying KECCAK permutation
			for(size_t rc = 0; rc < rounds_count; rc++) {
				// THETA
				int_t sheet[5] = {0};
				for (int x = 0; x < 5; x++) {	// traverse throught sheets
					sheet[x] ^= st[x]^st[x+5]^st[x+10]^st[x+15]^st[x+20];
				}
				for (int x = 0; x < 5; x++) {
					for (int y = 0; y < 5; y++) {
						st[x + y*5] ^= sheet[(x+4)%5] ^ rotl(sheet[(x+1)%5], 1);
					}
				}
				// RHO & PI
				int_t lane1 = rotl(st[1], rho_off[1]);
				for(int i = 0; i < 23; i++) {
					st[pi_jmp[i]] = rotl(st[pi_jmp[i+1]], rho_off[pi_jmp[i+1]]);
				}
				st[pi_jmp[23]] = lane1;
				// CHI
				for(int y = 0; y < 25; y += 5) {	// traverse through rows
					sheet[0] = st[y];
					sheet[1] = st[y+1];
					for(int x = 0; x < 3; x++) {
						st[y+x] ^= (~st[y+(x+1)]) & st[y+(x+2)];
					}
					st[y+3] ^= (~st[y+4]) & sheet[0];
					st[y+4] ^= (~sheet[0]) & sheet[1];
				}
				// IOTA
				st[0] ^= iota_rc[rc];
			}
		} // end round_permutation()

		//--------------------------------------------
		void absorbing(const byte *start, const byte *end, size_t size)
		{	// Absorbing part of input [start, end] with state array
			for(const byte* cur = start; cur != end; cur++)
				st_raw[cur - start] ^= *cur;
			if(size < rate) {


			}
			keccap_p();
		} // end absorbing()


		//--------------------------------------------
		void absorbing(const std::vector<int_t> &data) noexcept
		{	// Absorbing input data with state array
			const int absorp_num = data.size() * EIGHT_BYTES / rate;
			const int cur_block_size = rate / EIGHT_BYTES;

			for(int i = 0; i < absorp_num; i++) {
				auto start = data.begin() + 	i*cur_block_size;
				auto end   = data.begin() + (i+1)*cur_block_size;
				state_XOR_data(start, end);
				keccap_p();
			}
		} // end absorbing()

		//------------------------------------
		std::vector<byte> squeezing() noexcept
		{	// Squeezing part of the "sponge" construction.
			// Getting the message digest (hash)
			std::vector<byte> digest(digest_size, 0);

			size_t squee_out = 0;	// additional calculations need for XOF
			for(size_t i = 0; i < (digest_size/rate + 1); i++) {
				size_t n_to_squee = std::min((digest_size - squee_out), rate);
				for(size_t j = squee_out; j < squee_out + n_to_squee; j++)
					digest[j] = st_raw[j - squee_out];
				squee_out += n_to_squee;

				if(squee_out < digest_size)
					keccap_p();
			}
			return(digest);
		} // end absorbing()


	protected:		// Auxiliary functions
		//------------------------------------------------
		inline int_t rotl(int_t n, size_t offset) noexcept
		{	// left-rotating the value of <n> by <offset> positions
			// If C++20 is used may be replaced by "std::rotl"
			return((n << offset) | (n >> (sizeof(n)*EIGHT_BITS - offset)));
		}

		//------------------------------------------------
		inline void state_XOR_data(vec_iter start, vec_iter end) noexcept
		{
			for(int i = 0; i < (end - start); i++) {
				st[i] = st[i] ^ *(start + i);
			}
		}


	private:
		union {
			int_t st[STATE_SIZE];					// State (5 * 5 * w)
			byte  st_raw[STATE_SIZE*sizeof(int_t)];	// State as byte array
		};

		size_t digest_size;
		size_t capacity;
		size_t rate;
		size_t rounds;
		int_t  domain;	//domain separation: '0b10' for SHA3, '0b1111' for SHAKE
		size_t suff_len;	// length in bits of the domain suffix
	};  // end class keccak_p

} // end namespace sha3

//------------------------------------------------------------------------------
#endif /* SHA3_EC_H_ */
