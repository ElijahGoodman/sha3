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
#include <bitset>
#include <fstream>
#include <algorithm>
#include <exception>


//==============================================================================

#define FILE_NAME "SHA3-256_Msg30.txt"

typedef unsigned long long int_type;
typedef unsigned int size_type;

// --- Constants ---
constexpr size_type b = 200;				// b - width of KECCAK-p permutation, bytes
constexpr size_type digest = 32;			// i.e.;  digest (hash) length in bytes
constexpr size_type capacity = digest * 2;	// in bytes
constexpr size_type rate = b - capacity;	// in bytes
constexpr size_type w = sizeof(int_type);	// length of a lane, in bytes (== 8)
constexpr int BITS_IN_8_BYTES = 64;
constexpr int SUFFIX_LENGTH = 2;
constexpr int BITS_IN_BYTE = 8;
constexpr int PADDING_ONES = 2;

constexpr int_type array_of_ones[64] = {
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
inline int_type cycled_shift_right(int_type number, size_type offset)
{
	return ((number << offset) | (number >> (BITS_IN_8_BYTES - offset)));
}

// --- Cycled shift number right
inline int_type cycled_shift_left(int_type number, size_type offset)
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

// --- Print State ---		// for debugging
void print_state(const std::vector<int_type>& data, const std::string& title)
{
	std::cout << title;
	std::cout << std::setfill('0');
	for(int i = 0; i < 5; i++) {
		for (int j = 0; j < 5; j++) {
			std::cout << std::dec << "[" << j << ", " << i << "] = "
				<< std::hex  << std::uppercase
				<< std::setw(sizeof(int_type) * 2) << data[5*i + j] << '\n';
		}
	}
	std::cout << "-------------------\n";
}


//==============================================================================
// input data structure -- vector of <int_type> values
struct InputData
{
public:
	InputData(const std::string &str)
	: input_str(str)
	{
		initialization();
	}

	// Initialization
	void initialization()
	{
		this->len_in_bits = this->input_str.length();
		this->modified_size_in_bits = this->len_in_bits + SUFFIX_LENGTH;
		int temp = this->len_in_bits / BITS_IN_BYTE;
		this->len_in_bytes = (this->len_in_bits % BITS_IN_BYTE) ? (temp + 1) : temp;

		// debugging
		std::cout << "len_in_bits = " << len_in_bits << " | len_in_bytes = "
				  << len_in_bytes << "\n";
	//	std::cout << "len with suffix: " << this->modified_size_in_bits << '\n';

		// determine the required size of the input data.
		//  ---- first, determine number of bits to padding
		this->bits_to_padding = modulo(-this->modified_size_in_bits - PADDING_ONES,
								 rate*BITS_IN_BYTE);
		// additionally take into account two digits "11"
		this->bits_to_padding += PADDING_ONES;

		this->bytes_to_padding = this->bits_to_padding / BITS_IN_BYTE;
		this->bytes_to_padding += (this->bits_to_padding % BITS_IN_BYTE) ? 1 : 0;

	//	std::cout << "Required " << bits_to_padding << " bits to padding\n";
	//	std::cout << "// Required " << bytes_to_padding << " bytes to padding\n";

		// reserve required size of the input data (resize vector and fill it by '0'-s)
		this->data_size = (this->len_in_bits + SUFFIX_LENGTH + this->bits_to_padding) /
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
		domain_separation_and_padding();

		std::cout << "\n";
		//print_data();
		//print_data1();
	}

	// ----------------------------------
	// domain separation and padding rule
	void domain_separation_and_padding()
	{
		// ------------ adding suffix for domain separation
		// determine the bit & byte number after which we must to add a suffix
		int current_bit = (this->len_in_bits % BITS_IN_8_BYTES) - 1;
		int current_lane = this->len_in_bits / BITS_IN_8_BYTES;

	//	std::cout << "\nLast message byte " << current_lane << ' '
	//			  << " bit #" << current_bit << "\n\n";

		current_bit += SUFFIX_LENGTH;
		current_lane += (current_bit >= BITS_IN_8_BYTES) ? 1 : 0;
		current_bit = current_bit % BITS_IN_8_BYTES;		// truncate

	//	std::cout << "Suffix appends in lane " << current_lane << ' '
	//			  << " In placed bit #" << current_bit << '\n';

		this->data[current_lane] |= array_of_ones[current_bit]; // M || 01

		// ------------- add padding (if needed !!!)
		if(this->bits_to_padding) {			/// ALWAYS NEED PADDING !!!
			current_bit += 1;
			current_lane += (current_bit >= BITS_IN_8_BYTES) ? 1 : 0;
			current_bit = current_bit % BITS_IN_8_BYTES;		// truncate

		//	std::cout << "First padding bit in lane " << current_lane << ' '
		//			  << " In placed bit #" << current_bit << '\n';

			// add first bit ( 1 )
			this->data[current_lane] |= array_of_ones[current_bit];

			// == intermediate bits are already equal to 0 ==

			// add last bit ( 1 )
			this->data[this->data_size-1] |= array_of_ones[63]; // 0x1000000000000000

			// save modified size
			this->modified_size_in_bits += this->bits_to_padding;
			// debugging
		//	std::cout << "modified_size_in_bits = " << this->modified_size_in_bits << '\n';
		}
	}

	// --- Transform input string (in bits) to the array of integers ---
	void string_to_int_array()
	{
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
		}
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

	void print_data1()		// for debugging  | little-endian (GCC + Window8)
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
	std::vector<int_type> data;
	size_type data_size;
	size_type len_in_bits;
	size_type bits_to_padding;
	int modified_size_in_bits;	// data size after appending

public:								// temporary variable
	size_type len_in_bytes;			// what for?
	size_type bytes_to_padding;
};


//==============================================================================
//==== SHA3 FUNCTIONS ====
//==============================================================================
// --- KECCAK-p Permutation ---
void KECCAK_p(std::vector<int_type> &state)
{
	// !!!!!!!!!!!!!! WORK IN PROGRESS !!!!!!!!!!!!!!!!!!!!!!!!!
	
	
	// 1. THETA
	std::vector<int_type> theta_state_left(5, 0);
	std::vector<int_type> theta_state_right(5, 0);

	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 5; j++) {
			theta_state_left[j] = theta_state_left[j] ^ state[i*5 + j];
			theta_state_right[j] = theta_state_right[j] ^ 
									cycled_shift_left(state[i*5 + j], 1);
		}
	}

	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 5; j++) {
			state[i * 5 + j] = state[i * 5 + j] ^
							   theta_state_left[modulo(i - 1, 5)] ^
							   theta_state_right[modulo(i + 1, 5)];
		}
	}

	print_state(state, "State after THETA:\n");

	return;
} // end KECCAK_p()


// --- XOR State and Data
void State_XOR_Data(std::vector<int_type> &state, const std::vector<int_type> data)
{
	for(int i = 0; i < rate / w; i++) {
		state[i] = state[i] ^ data[i];

	}

	return;
}


// --- Sponge function ---
void Sponge(std::vector<int_type> &state, const std::vector<int_type> data)
{
	int rounds_count = 1;

	State_XOR_Data(state, data);

	print_state(state, "State:\n");		// debugging

	for(int i = 0; i < rounds_count; i++) {


		KECCAK_p(state);



	}

	return;
} // end Sponge()





//==============================================================================
int main(int, char* [])
{
	std::cout << "Check connection...\n";

	// ------------------
	// Get Input data
	// length = 62
	//std::string input_str{"11000101110001011100010111000101110001011100010111000101110001"};
	// length = 63
	//std::string input_str{"110001011100010111000101110001011100010111000101110001011100010"};
	// length = 64
	//std::string input_str{"1100010111000101110001011100010111000101110001011100010111000101"};

	//std::string input_str{""};		// length = 0
	//std::string input_str{"11001"};	// length = 5
	std::string input_str{"110010100001101011011110100110"};	// length = 30

/*
	std::string input_str{		// 1630
"1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
110001011100010111000101110001"
	};
*/

/*
	std::string input_str{		// length near rate
"1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111000101\
1100010111000101110001011100010111000101110001011100010111"
	};
*/

	std::cout << "SHA3-256 Initial parameters:" << "\n-------------------\n";
	std::cout << "Digest - " << digest * 8 << '\n';
	std::cout << "Rate - " << rate * 8 << '\n';
	std::cout << "Capacity - " << capacity * 8 << '\n';
	std::cout << "Suffix - 10\n" << "\n-------------------\n";

	std::cout << "Input data: " << input_str << "\n-------------------\n";

	// Initial State -- array 5 * 5 * w,  all values are 0-s
	std::vector<int_type> State(5 * 5, 0);

	// Setup input data from input string
	InputData input_data(input_str);

	Sponge(State, input_data.get_data());

















	std::cout << "\n-------------------\n" << "End.\n";
	return(0);
}

//==============================================================================

