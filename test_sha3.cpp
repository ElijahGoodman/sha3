/* 
 * test_sha3.cpp
 * 2022 Copyright © by Elijah Coleman
 */

//==============================================================================

#include "sha3_ec.h"

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

//==============================================================================
//=== FACILITIES ===
//==============================================================================

// convert vector of byte (unsigned char) to std::string
std::string byte_vec_to_str(const std::vector<chash::byte>& vec,
							const char *separator = "",
							bool uppercase = true,
							chash::size_t byte_in_line = 0)
{   
	const char digit_upper[] = { '0', '1', '2', '3', '4', '5', '6', '7',
								 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	const char digit_lower[] = { '0', '1', '2', '3', '4', '5', '6', '7',
								 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

 	size_t str_len = vec.size() * 3;
	if (0 == byte_in_line)
		byte_in_line = str_len;
	else
		str_len += vec.size() / byte_in_line;
	std::string res("");
	res.reserve(str_len);
	for (chash::size_t i = 0; i < vec.size(); i++) {
		res += uppercase ? digit_upper[vec[i] >> 4] : digit_lower[vec[i] >> 4];
		res += uppercase ? digit_upper[vec[i] & 15] : digit_lower[vec[i] & 15];
		res += separator;
		if (!((i + 1) % byte_in_line))
			res += '\n';
	}
	if(separator != "")
		res.pop_back();
	if ('\n' == res[res.length() - 1])
		res.pop_back();
	return (res);
}

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

	//chash::SHA3_224 obj;
	//chash::SHA3_256 obj;
	//chash::SHA3_384 obj;
	chash::SHA3_512 obj;
	//chash::SHAKE128 obj;
	//chash::SHAKE256 obj;
	//obj.set_digest_size(1208);

	std::cout << obj.get_hash_type() << "\n\n";

	for(const std::pair<int, std::string> &input_str : input_strings) {
		//std::string input_str = input_strings[1630];
	 	std::cout << "-------------------\n";
		std::cout << "Input data (message length = " << std::dec
				<< input_str.first << "):\n" << input_str.second << "\n";
		
		auto md = obj.get_digest(input_str.second.c_str(), input_str.first);

		std::cout << byte_vec_to_str(md, " ", true, 16) << "\n";

		/*
		int i = 0;
		std::cout << "Message digest:\n" << std::hex;
		for(const auto c : md) {
			std::cout << std::setw(2) << std::setfill('0') << std::uppercase
					  << static_cast<int>(c) << " ";
			if(!((i+1)%16))
						std::cout << '\n';
			i++;
		}
		*/
		std::cout << "\n";
	}

	std::cout << "\n-------------------\n" << "End.\n";
	return(0);
}

/*
		//----------------------------
		std::vector<byte> file_digest(std::ifstream &input_file)
		{   // Return the digest of file (processed as a sequence of bytes)
			// NOTES: - The caller must provide that the file stream is valid
			//          and available.
			//        - If the input file stream is not valid, returns nullptr
			if (input_file.is_open()) {
				std::streampos a;
			}
			else
				return(nullptr);
		} // end file_digest()

  std::ifstream is ("test.txt", std::ifstream::binary);
  if (is) {
	// get length of file:
	is.seekg (0, is.end);
	int length = is.tellg();
	is.seekg (0, is.beg);

	char * buffer = new char [length];

	std::cout << "Reading " << length << " characters... ";
	// read data as a block:
	is.read (buffer,length);

	if (is)
	  std::cout << "all characters read successfully.";
	else
	  std::cout << "error: only " << is.gcount() << " could be read";
	is.close();

	// ...buffer contains the entire file...
	delete[] buffer;
  }

  // reading an entire binary file
  streampos size;
  char * memblock;

  ifstream file ("example.bin", ios::in|ios::binary|ios::ate);
  if (file.is_open())
  {
	size = file.tellg();
	memblock = new char [size];
	file.seekg (0, ios::beg);
	file.read (memblock, size);
	file.close();

	cout << "the entire file content is in memory";

	delete[] memblock;
  }
  else cout << "Unable to open file";



*/


//==============================================================================

