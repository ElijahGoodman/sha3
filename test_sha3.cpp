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
//=== FACILITIES ===
//==============================================================================


//==============================================================================
int main(int, char* [])
{
	std::cout << "Check connection...\n";

	//std::cout << std::hex << (0x00000000000000FF << 8) << " " << (0x00000000000000FF << 16);


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
//		{344, "The quick brown fox jumps over the lazy dog"},
//		{352, "The quick brown fox jumps over the lazy dog."},
/*
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
*/		
	};

/*
	const chash::size_t digest_size = 224;				// SHA3-224
	const chash::size_t capacity = 448;
	const chash::int_t sha3_domain = chash::kSHA3_domain;
*/
/*
	const chash::size_t digest_size = 256;				// SHA3-256
	const chash::size_t capacity = 512;
	const chash::int_t sha3_domain = chash::kSHA3_domain;
*/
/*
	const chash::size_t digest_size = 384;				// SHA3-384
	const chash::size_t capacity = 768;
	const chash::int_t sha3_domain = chash::kSHA3_domain;
*/
/*
	const chash::size_t digest_size = 512;				// SHA3-512
	const chash::size_t capacity = 1024;
	const chash::int_t sha3_domain = chash::kSHA3_domain;
*/
/*
	const chash::size_t digest_size = 4096;				// SHAKE-128
	const chash::size_t capacity = 256;
	const chash::int_t sha3_domain = chash::kSHAKE_domain;
*/

	const chash::size_t digest_size = 4096;				// SHAKE-256
	const chash::size_t capacity = 512;
	const chash::int_t sha3_domain = chash::kSHAKE_domain;


	chash::Keccak<digest_size, capacity, sha3_domain> obj;

	std::cout << (sha3_domain == chash::kSHA3_domain ? "SHA3-" : "SHAKE-")
			<< (digest_size*8) << "\n\n";

	for(const std::pair<int, std::string> &input_str : input_strings) {
		//std::string input_str = input_strings[1630];
	 	std::cout << "-------------------\n";
		std::cout << "Input data (message length = " << std::dec
				<< input_str.first << "):\n" << input_str.second << "\n";
		//std::cout << "Input data: " << input_str << "\n\n";
		
		//auto md = obj.MD(input_strings[0], 0);
		//auto md = obj.MD(input_strings[30], 30);
		//auto md = obj.MD(input_str, 1630);

		//auto md = obj.MD(input_str.second, input_str.first);
		auto md = obj.get_digest(input_str.second.c_str(), input_str.first);

		int i = 0;
		std::cout << "Message digest:\n" << std::hex;
		for(const auto c : md) {
			std::cout << std::setw(2) << std::setfill('0') << std::uppercase
					  << (int)c << " ";
			if(!((i+1)%16))
						std::cout << '\n';
			i++;
		}
		std::cout << "\n";
	}

	std::cout << "\n-------------------\n" << "End.\n";
	return(0);
}

//==============================================================================

