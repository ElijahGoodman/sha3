/* 
 * test_sha3.cpp
 * 2022 Copyright © by Elijah Coleman
 */

//==============================================================================

#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <bitset>
#include <fstream>
#include <algorithm>
#include <exception>
#include <iterator>

#include "sha3_ec.h"

//==============================================================================

typedef unsigned long long int_type;
typedef unsigned int size_type;

using d_iter = std::vector<int_type>::const_iterator;

// --- Constants ---
const size_type b = 200;				// b - width of KECCAK-p permutation, bytes

const int BITS_IN_8_BYTES = 64;
const int_type W64 = 64;
//const int SUFFIX_LENGTH = 2;
const int BITS_IN_BYTE = 8;
const int BYTES_IN_INT64 = 8;
const int PADDING_ONES = 2; 	// Two bits of padding which always must been "11"
const bool BIT_ORIENTED = true;
const int_type SHA3_PADD = 0b110;			// Paddings for SHA3 and SHAKE
const int_type SHAKE_PADD = 0b11111;

//const size_type digest_length = 32;	    // i.e.;  digest (hash) length in bytes
//constexpr size_type capacity = 64;		// in bytes
//constexpr size_type rate = b - capacity;	// in bytes
//constexpr size_type w = sizeof(int_type);	// length of a lane, in bytes (== 8)

// Parameters of Sponge construction
struct sha3_param
{
public:
	sha3_param(int d_len = 32, int c = 64, int suf_len = 2, 
			   bool bit_byte = false, int_type p = 0b110)
	: digest_length(d_len),
	  rate(b-c),
	  capacity(c),
	  suffix_length(suf_len),
	  bit_oriented(bit_byte),
	  padd(p)
	{	// By default - SHA3_256 (digest=256, capacity=512, suffix = "10")
	}

public:
	int digest_length;
	int rate;
	int capacity;
	int suffix_length;
	bool bit_oriented;
	int_type padd;
};

const int_type array_of_ones[64] = {
	0x0000000000000001, 0x0000000000000002, 0x0000000000000004, 0x0000000000000008,
	0x0000000000000010, 0x0000000000000020, 0x0000000000000040, 0x0000000000000080,
	0x0000000000000100, 0x0000000000000200, 0x0000000000000400, 0x0000000000000800,
	0x0000000000001000, 0x0000000000002000, 0x0000000000004000, 0x0000000000008000,
	0x0000000000010000, 0x0000000000020000, 0x0000000000040000, 0x0000000000080000,
	0x0000000000100000, 0x0000000000200000, 0x0000000000400000, 0x0000000000800000,
	0x0000000001000000, 0x0000000002000000, 0x0000000004000000, 0x0000000008000000,
	0x0000000010000000, 0x0000000020000000, 0x0000000040000000, 0x0000000080000000,
	0x0000000100000000, 0x0000000200000000, 0x0000000400000000, 0x0000000800000000,
	0x0000001000000000, 0x0000002000000000, 0x0000004000000000, 0x0000008000000000,
	0x0000010000000000, 0x0000020000000000, 0x0000040000000000, 0x0000080000000000,
	0x0000100000000000, 0x0000200000000000, 0x0000400000000000, 0x0000800000000000,
	0x0001000000000000, 0x0002000000000000, 0x0004000000000000, 0x0008000000000000,
	0x0010000000000000, 0x0020000000000000, 0x0040000000000000, 0x0080000000000000,
	0x0100000000000000, 0x0200000000000000, 0x0400000000000000, 0x0800000000000000,
	0x1000000000000000, 0x2000000000000000, 0x4000000000000000, 0x8000000000000000,
};

// ===== KECCAK Constants ======
// For RHO
/*constexpr int_type rho_offsets[25] = {
			0,   1 % W64, 190 % W64,  28 % W64,  91 % W64,
	 36 % W64, 300 % W64,   6 % W64,  55 % W64, 276 % W64,
	  3 % W64,  10 % W64, 171 % W64, 153 % W64, 231 % W64,
	105 % W64,  45 % W64,  15 % W64,  21 % W64, 136 % W64,
	210 % W64,  66 % W64, 253 % W64, 120 % W64,  78 % W64
};
*/
// For RHO + PI
static const unsigned rho_offsets[25] = {
	  	  0,   1 % W64, 190 % W64,  28 % W64,  91 % W64,
   36 % W64, 300 % W64,   6 % W64,  55 % W64, 276 % W64,
    3 % W64,  10 % W64, 171 % W64, 153 % W64, 231 % W64,
  105 % W64,  45 % W64,  15 % W64,  21 % W64, 136 % W64,
  210 % W64,  66 % W64, 253 % W64, 120 % W64,  78 % W64
};

// PI (rotation)
const int_type pi_jumps[24] = {
	1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18,
	17, 11, 7, 10
};

// IOTA
const int_type iota_rc[24] = {
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B,	0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009,	0x000000008000000A,
	0x000000008000808B,	0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008
};

//==============================================================================
//=== FACILITIES ===
//==============================================================================
// --- Correct modulo operation ---
int modulo(int num, int denom)
{
	int rem = num % denom;
	return( (rem >= 0) ? rem : (std::abs(denom) - std::abs(rem)) );
}

// --- Cycled shift number left
inline int_type cycled_shift_left(int_type number, size_type offset)
{
	return ((number << offset) | (number >> (BITS_IN_8_BYTES - offset)));
}

// --- Cycled shift number right
inline int_type cycled_shift_right(int_type number, size_type offset)
{
	return ((number >> offset) | (number << (BITS_IN_8_BYTES - offset)));
}

// --- Transform string like "1011101..." to integer FIPS PUB 202 Algorithm 11.
int_type b2h(std::string::const_iterator start,
			 std::string::const_iterator end)
{
	int_type value = 0;
	size_type n = (end - start);
	for(size_type i = 0; i < n; i++) {
		if('1' == *(start + i))
			value |= array_of_ones[i];
	}
	return value;
}

int state_to_chars(const std::vector<int_type> &state,
				   std::vector<unsigned char> &data, int num_of_bytes)
{
	int count = 0;
	int num_of_lanes = num_of_bytes / BYTES_IN_INT64;
	num_of_lanes += (num_of_bytes % BYTES_IN_INT64) ? 1 : 0;

	for(int i = 0; i < num_of_lanes; i++) {
		int_type number = state[i];
		unsigned char *c = reinterpret_cast<unsigned char*>(&number);
		for(int i=0; (i < BYTES_IN_INT64)&&(count < num_of_bytes); i++) {
			data.push_back(c[i]);
			count++;
		}
	}

	return (count);
}

// --- Print vector ---		// for debugging
void print_vector(const std::vector<int_type>& data, const std::string& title)
{
	std::cout << title;
	std::cout << std::setfill('0');
	int i=0;
	for(int_type word : data) {
		std::cout << std::dec << std::setw(3) << i << ' ' << std::hex
				  << std::uppercase
				  << std::setw(sizeof(int_type) * 2) << word << '\n';
		i++;
	}
	std::cout << "-------------------\n";
}

// --- Print vector<int> in hexadecimal form ---		// for debugging
void print_data_raw(const std::vector<int>& data, const std::string& title)
{
	std::cout << title;
	for(const int& number : data ) {
		std::cout << std::setw(2) << std::hex << std::setfill('0')
				  << std::uppercase << number << ' ';
	}
	std::cout << "\n-------------------\n";
}


// --- Print vector<int_type> in hexadecimal form ---		// for debugging
void print_modified_data_raw(const std::vector<int_type>& data, const std::string& title)
{
	std::cout << title;

	for(const int_type& number : data ) {
		int_type lane = number;
		unsigned char *c = reinterpret_cast<unsigned char*>(&lane);
		for(int i = 0; i < sizeof(int_type); i++) {
			std::cout << std::setw(2) << std::hex
					<< std::setfill('0') << std::uppercase
					<< static_cast<unsigned int>(c[i]) << ' ';
		}
	}
	std::cout << "\n-------------------\n";
}

// --- Print State ---		// for debugging
void print_state(const std::vector<int_type>& data, const std::string& title)
{
	std::cout << title;
	std::cout << std::setfill('0');
	for(int y = 0; y < 5; y++) {
		for (int x = 0; x < 5; x++) {
			std::cout << std::dec << "[" << x << ", " << y << "] = "
				<< std::hex  << std::nouppercase
				<< std::setw(sizeof(int_type) * 2) << data[x + y*5] << '\n';
		}
	}
	std::cout << "-------------------\n";
}

// --- Print State ---		// for debugging
void print_state_raw(const std::vector<int_type>& state, const std::string& title)
{
	std::cout << title;

	int i=0;
	for(int x = 0; x < 5; x++) {
		for(int y = 0; y < 5; y++) {
			int_type lane = state[x*5 + y];
			unsigned char *c = reinterpret_cast<unsigned char*>(&lane);
			for(int i = 0; i < sizeof(int_type); i++) {
				std::cout << std::setw(2) << std::setfill('0') << std::uppercase
						  << static_cast<unsigned int>(c[i]) << ' ';
			}
			if(i%2)
				std::cout << '\n';
			i++;
		}
	}
	std::cout << "\n-------------------\n";
}

// --- Print State ---		// for debugging
void print_number(int_type number)
{
	unsigned char *c = reinterpret_cast<unsigned char*>(&number);
	for(int i = 0; i < sizeof(int_type); i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << std::uppercase
				  << static_cast<unsigned int>(c[i]) << ' ';
	}
}


//==============================================================================
// input data structure -- vector of <int_type> values
struct InputData
{
public:
	InputData(const std::string &str, int length)
	: input_str(str), len_in_bits(length)
	{
	}

	// Conversion hexadecimal string to vector of integers (through byte string)
	void data_convertion(const sha3_param &param)
	{
		std::cout << "Input string:\n";
		std::cout << input_str << "\n";
		std::cout << "Length in bit: " << std::dec << this->len_in_bits << '\n';

		// !!!! Input string must been 2*m size (m - integer) !!!!

		// Convert input string to vector<int> bytes
		for(int c = 0; c < this->input_str.size(); c += 2) {
			std::string num{this->input_str[c], this->input_str[c+1]};
			raw_data.push_back(std::stoi(num, nullptr, 16));
		}

		std::cout << "Size = " << std::dec << raw_data.size() << "\n";
		//print_data_raw(raw_data, "Raw input data:\n");

		this->modified_size_in_bits = this->len_in_bits + param.suffix_length;
		int temp = this->len_in_bits / BITS_IN_BYTE;
		this->len_in_bytes = (this->len_in_bits % BITS_IN_BYTE) ? (temp + 1) : temp;

		// determine the required size of the input data.
		//  ---- first, determine number of bits to padding
		this->bits_to_padding = modulo(-this->modified_size_in_bits - PADDING_ONES,
									   param.rate*BITS_IN_BYTE);
		// additionally take into account two digits "11"
		this->bits_to_padding += PADDING_ONES;

		this->bytes_to_padding = this->bits_to_padding / BITS_IN_BYTE;
		this->bytes_to_padding += (this->bits_to_padding % BITS_IN_BYTE) ? 1 : 0;

	//	std::cout << "Required " << bits_to_padding << " bits to padding\n";
	//	std::cout << "// Required " << bytes_to_padding << " bytes to padding\n";

		// reserve required size of the input data (resize vector and fill it by '0'-s)
		this->data_size = (this->len_in_bits + param.suffix_length + this->bits_to_padding) /
						  BITS_IN_8_BYTES;
		this->data.reserve(this->data_size);
		this->data.resize(this->data_size, 0);

		std::cout << "Size of vector<int_type> = " << std::dec << data.size() << "\n";

		convert_raw_data();
		//print_data();

		domain_separation_and_padding(param);

		//print_data();
	}

	// Convert raw data (vector<byte>) to vector<int_type>
	void convert_raw_data()
	{
		for(int i = 0; i < raw_data.size(); i++) {
			int j = i/BYTES_IN_INT64;
			int_type temp = static_cast<int_type>(raw_data[i]) << ((i%BYTES_IN_INT64)*BYTES_IN_INT64);
			data[j] |= temp;
		}
	}


	// Initialization
	void initialization(const sha3_param &param)
	{
		this->len_in_bits = this->input_str.length();
		this->modified_size_in_bits = this->len_in_bits + param.suffix_length;
		int temp = this->len_in_bits / BITS_IN_BYTE;
		this->len_in_bytes = (this->len_in_bits % BITS_IN_BYTE) ? (temp + 1) : temp;

		// debugging
		std::cout << std::dec
				  << "len_in_bits = " << len_in_bits << " | len_in_bytes = "
				  << len_in_bytes << "\n";
	//	std::cout << "len with suffix: " << this->modified_size_in_bits << '\n';

		// determine the required size of the input data.
		//  ---- first, determine number of bits to padding
		this->bits_to_padding = modulo(-this->modified_size_in_bits - PADDING_ONES,
									   param.rate*BITS_IN_BYTE);
		// additionally take into account two digits "11"
		this->bits_to_padding += PADDING_ONES;

		this->bytes_to_padding = this->bits_to_padding / BITS_IN_BYTE;
		this->bytes_to_padding += (this->bits_to_padding % BITS_IN_BYTE) ? 1 : 0;

	//	std::cout << "Required " << bits_to_padding << " bits to padding\n";
	//	std::cout << "// Required " << bytes_to_padding << " bytes to padding\n";

		// reserve required size of the input data (resize vector and fill it by '0'-s)
		this->data_size = (this->len_in_bits + param.suffix_length + this->bits_to_padding) /
						  BITS_IN_8_BYTES;
		this->data.reserve(this->data_size);
		this->data.resize(this->data_size, 0);

	//	std::cout << "\nSize of input data array: " << data_size << '\n';

		try {
		// transform input string to the array of integers
		string_to_int_array();
		} catch (std::exception &e) {
			std::cout << e.what() << '\n';
		} catch (...) {
			std::cout << "Oops! Something goes wrong!\n";
		}

		// applying domain separation and padding rule
		domain_separation_and_padding(param);

		std::cout << "\n";
		//print_data();
		//print_data1();
	}

	// ----------------------------------
	// domain separation and padding rule
	void domain_separation_and_padding(const sha3_param &param)
	{
		int cur_lane = this->len_in_bits / (BITS_IN_BYTE * BYTES_IN_INT64);
		int cur_bit = this->len_in_bits % (BITS_IN_BYTE * BYTES_IN_INT64);


		std::cout << "Current lane: " << std::dec << cur_lane << "\n";
		std::cout << "Current bit: " << std::dec << cur_bit << "\n";

		// add suffix and first bit of padding
		data[cur_lane] |= param.padd << cur_bit;;
		
		// if total size > 64 bit, i.e. we have an overflow
		int overflow = (cur_bit + param.suffix_length + 1) - BITS_IN_8_BYTES;
		//std::cout << "Overflow: " << std::dec << overflow << "\n";
		if (overflow > 0) {
			data[cur_lane + 1] = param.padd >> (param.suffix_length + 1 - overflow);
		}

		// add last byte of padding
		this->data[this->data_size - 1] |= array_of_ones[63]; // 0x1000000000000000
	}

	// --- Transform input string (in bits) to the array of integers ---
	void string_to_int_array()
	{
		std::cout << "\nInput string:\n";
		//int_type current_number = 0;
		std::string::const_iterator start = this->input_str.begin(),
									end = this->input_str.begin();
		for(size_type i = 0; i <= this->len_in_bits / BITS_IN_8_BYTES; i++) {
			if((i+1)*BITS_IN_8_BYTES > this->len_in_bits)
				end = this->input_str.end();
			else
				end += BITS_IN_8_BYTES;
			//current_number = str_to_int(start, end);
			// arr.push_back(str_to_int(start, end));	// if vector is not resized
			this->data[i] = b2h(start, end);			// if vector is resized
			start = end;
			//std::cout << std::dec << i
			//		  << std::hex << " current number is " << current_number << '\n';
			print_number(this->data[i]);
		}
		std::cout << "\n";
	}

	// --------------
	void print_data()		// for debugging
	{
		std::cout << std::setfill('0');
		int i=0;
		for(int_type lane : data) {
			std::cout << std::dec << std::setw(3) << i << ' ' << std::hex
					  << std::uppercase
					  << std::setw(sizeof(int_type) * 2) << lane << '\n';
			i++;
		}
		std::cout << "-------------------\n";
	}

	void print_data1()		// for debugging  | mixed-endian (GCC + Window8)
	{
		int i=0;
		for(int_type lane : data) {
			//std::cout << std::dec << std::setw(3) << i << ' ' << std::hex
			//		  << std::setw(sizeof(int_type) * 2) << lane << '\n';

			std::cout << std::dec << std::setw(2) << i << "   " << std::hex;
			unsigned char *c = reinterpret_cast<unsigned char*>(&lane);
			for(int j = 0; j < sizeof(int_type); j++) {
				std::cout << std::setw(2) << std::setfill('0') << std::uppercase
						  << static_cast<unsigned int>(c[j]) << ' ';
			}
			std::cout << '\n';
			i++;
		}
		std::cout << "-------------------\n";
	}

	// --------------
	size_type size() const {  return data_size; }
	std::vector<int_type> get_data() const { return data; }

public:
	std::string input_str;
	size_type len_in_bits;
	std::vector<int> raw_data;
	std::vector<int_type> data;
	size_type data_size;
	size_type bits_to_padding;
	int modified_size_in_bits;	// data size after appending
	bool bit_oriented;

public:								// temporary variable
	size_type len_in_bytes;			// what for?
	size_type bytes_to_padding;
};


//==============================================================================
//==== SHA3 FUNCTIONS ====
//==============================================================================
// --- KECCAK-p Permutation ---
void KECCAK_p(std::vector<int_type> &state, const int_type round_constant)
{
	// !!!!!!!!!!!!!! WORK IN PROGRESS !!!!!!!!!!!!!!!!!!!!!!!!!
	// 1. THETA
	std::vector<int_type> theta_state_left(5, 0);
	std::vector<int_type> theta_state_right(5, 0);

	for (int x = 0; x < 5; x++) {
			theta_state_left[x] ^= state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
			theta_state_right[x] = cycled_shift_left(theta_state_left[x], 1);
	}
	for (int x = 0; x < 5; x++) {
		for (int y = 0; y < 5; y++) {
			//state[x + y*5] ^= theta_state_left[modulo(x-1, 5)] ^	//  (x+4)%5
			state[x + y*5] ^= theta_state_left[(x+4)%5] ^
							  theta_state_right[(x+1)%5];
		}
	}
//	print_state(state, "State after THETA:\n");
//	print_state_raw(state, "State after THETA:\n");
/*
	// 2. RHO
	for(int x = 0; x < 5; x++) {
		for(int y = 0; y < 5; y++) {
			state[x + y*5] = cycled_shift_left(state[x + y*5], rho_offsets[x + y*5]);
		}
	}
	print_state_raw(state, "State after RHO:\n");
	// 3. PI
	int_type pi_temp = state[1];
	for(int i = 0; i < 23; i++) {
		state[pi_jumps[i]] = state[pi_jumps[i+1]];
	}
	state[pi_jumps[23]] = pi_temp;
	print_state_raw(state, "State after PI:\n");
*/
	// 2. + 3. RHO + PI
	int_type pi_temp = cycled_shift_left(state[1], rho_offsets[1]);
//	std::cout << "RHO & PI:\n";
	for(int i = 0; i < 23; i++) {
		state[pi_jumps[i]] = cycled_shift_left(state[pi_jumps[i+1]],
											   rho_offsets[pi_jumps[i+1]]);
	}
	state[pi_jumps[23]] = pi_temp;
//	print_state_raw(state, "State after RHO + PI:\n");

	// 4. CHI
	// (~A[i]) = A[i] ^ 0xFFFFFFFFFFFFFFFF (i.e. A[i] xor 1)
	for(int y = 0; y < 25; y += 5) {		// traverse through rows
		int_type x1 = state[y];
		int_type x2 = state[y+1];
		for(int x = 0; x < 3; x++) {
			state[y+x] ^= (~state[y+(x+1)]) & state[y+(x+2)];
		}
		state[y+3] ^= (~state[y+4]) & x1;
		state[y+4] ^= (~x1) & x2;
	}
//	print_state_raw(state, "State after CHI:\n");

	// 5. IOTA
	state[0] ^= round_constant;
//	print_state_raw(state, "State after IOTA\n");

	return;
} // end KECCAK_p()

// --- KECCAK-f[1600, 24]
void KECCAK_f(std::vector<int_type> &state)
{
	const int round_count = 24;
	for(int i = 0; i < round_count; i++) {
		KECCAK_p(state, iota_rc[i]);
	}
}

// --- XOR State and Data
void State_XOR_Data(std::vector<int_type> &state, d_iter start, d_iter end)
{
	for(int i = 0; i < (end - start); i++) {
		state[i] = state[i] ^ *(start + i);
	}
	return;
}

// --- Sponge function ---
void Sponge(std::vector<int_type> &state, const std::vector<int_type> data,
			const sha3_param &param)
{
	// ABSORBING
	const int absorb_count = data.size()*BYTES_IN_INT64 / param.rate;
	const int data_part_size = param.rate / BYTES_IN_INT64;

	//std::cout << "Size " << data.size()*BYTES_IN_INT64 << " rate " << param.rate << '\n';
	std::cout << "Absorbing " << absorb_count << " times\n\n";

	for(int i = 0; i < absorb_count; i++) {
		d_iter start = data.begin() + i*data_part_size;
		d_iter end = data.begin() + (i+1)*data_part_size;
		State_XOR_Data(state, start, end);

	//	print_state(state, "State:\n");		// debugging

		KECCAK_f(state);

		//print_state(state, "State after permutation:\n");
	//	print_state_raw(state, "State after Permutation:\n\n");
	}


	// SQUEEZING
	std::vector<unsigned char> digest;		// DESIRED FUCKING DIGEST
	digest.reserve(param.digest_length+1);		// +1 byte just in case, bitch

	const int squeez_count = param.digest_length / param.rate + 1;

	std::cout << "Squeez_count = " << squeez_count << "\n\n";

	int bytes_squeezed_out = 0;
	for(int i=0; i < squeez_count; i++) {
		int need_to_squeezed = std::min((param.digest_length - bytes_squeezed_out), param.rate);
		bytes_squeezed_out += state_to_chars(state, digest, need_to_squeezed);

		if(bytes_squeezed_out < param.digest_length)
			KECCAK_f(state);
	}

	// print Digest
	//std::cout << "Digest size = " << std::dec << digest.size() << "\n";
	std::cout << "Digest (" << std::dec << digest.size() << " bytes):\n";
	for(int i = 0; i < digest.size(); i++) {
		std::cout << std::setw(2) << std::hex << std::uppercase
				  << std::setfill('0') << static_cast<int>(digest[i]) << " ";
		if(!((i+1)%16))
			std::cout << '\n';
	}

	return;
} // end Sponge()


//==============================================================================
int main(int, char* [])
{
	std::cout << "Check connection...\n";

	//sha3::keccak_p obj(256, sha3::SHA3_DOMAIN);
	chash::keccak obj(256);

	// Input data -- hexadecimal strings
	std::map<int, std::string> input_strings {
		{0, ""},				// MSG 0 bit
		{5, ""},				// MSG 5 bits
		{30, "SX{"},		// MSG 30 bits
		// MSG 1600 bits
		{1600, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
££££££££££££££££££££££££££££££££££££££££££££££££££££££££££"},
		// MSG 1605 bits
		{1605, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
££££££££££££££££££££££££££££££££££££££££££££££££££££££££££"},
		// MSG 1630 bits
		{1630, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££#"},
		// MSG 1088 bits
		{1088, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££"},
		// MSG 1087 bits
		{1087, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££#"},
		// MSG 1086 bits
		{1086, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££#"},
		// MSG 1085 bits
		{1085, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££"},
		// MSG 1084 bits
		{1084, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££"},
		// MSG 1083 bits
		{1083, "£££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££\
££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££££"}
	};

	//auto md = obj.MD(input_strings[0], 0);
	auto md = obj.MD(input_strings[5], 5);
	//auto md = obj.MD(input_strings[30], 30);

	std::cout << std::hex;
	for(const auto c : md) {
		std::cout << std::setw(2) << std::setfill('0') << (int)c << " ";
	}
	std::cout << "\n";

	//std::copy(md.begin(), md.end(), std::ostream_iterator<int>(std::cout, " "));

/*
	// ------------------
	// Input data -- hexadecimal strings
	std::map<int, std::string> input_strings {
		{0, "00"},				// MSG 0 bit
		{5, "13"},				// MSG 5 bits
		{30, "53587B19"},		// MSG 30 bits
		// MSG 1600 bits
		{1600, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3"},
		// MSG 1605 bits
		{1605, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A303"},
		// MSG 1630 bits
		{1630, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A323"},
		// MSG 1088 bits
		{1088, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3"},
		// MSG 1087 bits
		{1087, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A323"},
		// MSG 1086 bits
		{1086, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A323"},
		// MSG 1085 bits
		{1085, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A303"},
		// MSG 1084 bits
		{1084, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A303"},
		// MSG 1083 bits
		{1083, "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3\
A3A3A3A3A3A3A303"}
	};


	//sha3_param param{28, 56, 2, BIT_ORIENTED, 0b110};		// SHA3-224
	//sha3_param param{};								// {32, 64, 2, bit_oriented} SHA3-256
	//sha3_param param{48, 96, 2, BIT_ORIENTED, 0b110};		// SHA3-384
	//sha3_param param{64, 128, 2, BIT_ORIENTED, 0b110};	// SHA3-512
	//sha3_param param{512, 32, 4, BIT_ORIENTED, 0b11111};	// SHAKE128
	sha3_param param{512, 64, 4, BIT_ORIENTED, 0b11111};	// SHAKE256
*/
/*
	std::cout << "SHA3 Initial parameters:" << "\n-------------------\n";
	std::cout << "Digest - " << param.digest_length * 8 << '\n';
	std::cout << "Rate - " << param.rate * 8 << '\n';
	std::cout << "Capacity - " << param.capacity * 8 << '\n';
	std::cout << "Suffix - 10\n" << "\n-------------------\n";

	// Setup input data from input string
	//for(const std::pair<const std::string, int> &input_str : input_strings) {
	for(const std::pair<int, std::string> &input_str : input_strings) {
	//{
		//std::string input_str = input_strings[1];
		//std::cout << "Input data: " << input_str << "\n-------------------\n";

		InputData input_data(input_str.second, input_str.first);
		input_data.data_convertion(param);
		//print_modified_data_raw(input_data.get_data(), "Input data:\n");


		// Initial State -- array 5 * 5 * w,  all values are 0-s
		std::vector<int_type> State(5 * 5, 0);

		Sponge(State, input_data.get_data(), param);

		std::cout << "\n\n===================\n";
	}
*/
	std::cout << "\n-------------------\n" << "End.\n";
	return(0);
}

//==============================================================================

