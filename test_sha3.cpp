/* 
 * test_sha3.cpp
 * 2022 Copyright © by Elijah Coleman
 */

//==============================================================================

#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>

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
#include <cstring>

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
	if(std::strcmp(separator,"") != 0)
		res.pop_back();
	if ('\n' == res[res.length() - 1])
		res.pop_back();
	return (res);
}

//==============================================================================
int main(int, char* [])
{
	// Memory diagnostic
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

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
	chash::SHA3_224 obj;
	//chash::SHA3_256 obj;
	//chash::SHA3_384 obj;
	//chash::SHA3_512 obj;
	//chash::SHAKE128 obj;
	//chash::SHAKE256 obj;
	//obj.set_digest_size(4096);

	std::cout << obj.get_hash_type() << "\n\n";

	for(const std::pair<int, std::string> &input_str : input_strings) {
		//std::string input_str = input_strings[1630];
	 	std::cout << "-------------------\n";
		std::cout << "Input data (message length = " << std::dec
				<< input_str.first << "):\n" << input_str.second << "\n";
		
		auto md = obj.get_digest(input_str.second, input_str.first);

		std::cout << byte_vec_to_str(md, " ", true, 16) << "\n";


//		int i = 0;
//		std::cout << "Message digest:\n" << std::hex;
//		for(const auto c : md) {
//			std::cout << std::setw(2) << std::setfill('0') << std::uppercase
//					  << static_cast<int>(c) << " ";
//			if(!((i+1)%16))
//						std::cout << '\n';
//			i++;
//		}

		std::cout << "\n";
	}
*/
	chash::SHA3_224_IUF obj;
	//chash::SHA3_256_IUF obj;
	//chash::SHA3_384_IUF obj;
	//chash::SHA3_512_IUF obj;
	//chash::SHAKE128_IUF obj;
/*
	obj.set_digest_size(256);
	std::cout << obj.get_hash_type() << "\n\n";

	std::string empty_str = "";

	//obj.update("The quick brown fox jumps over the lazy dog");
	obj.update("The quick b");
	obj.update("row");
	obj.update("n fox jumps over the lazy do");
	obj.update("f");


	/*
	std::cout << "Message:\n" << input_strings[1630] << "\n";

	std::cout << "Absorbed " << obj.update(empty_str.begin(), empty_str.end()) << " bytes\n";
	std::cout << "Absorbed " << obj.update(empty_str.end(), empty_str.begin()) << " bytes\n";
	std::cout << "Absorbed " << obj.update(input_strings[1600].begin(), input_strings[1600].begin()) << " bytes\n";
	std::cout << "Absorbed " << obj.update(input_strings[1600].begin(), input_strings[1600].begin()+1) << " bytes\n";
	std::cout << "Absorbed " << obj.update(input_strings[1600].begin()+1, input_strings[1600].begin()+3) << " bytes\n";
	std::cout << "Absorbed " << obj.update(input_strings[1600].begin()+3, input_strings[1600].begin()+135) << " bytes\n";
	std::cout << "Absorbed " << obj.update(input_strings[1600].begin()+135, input_strings[1600].begin()+199) << " bytes\n";
	std::cout << "Absorbed " << obj.update(input_strings[1600].begin()+199, input_strings[1600].end()) << " bytes\n";
	*/
/*
	std::cout << "\nMessage digest:\n";
    std::cout << byte_vec_to_str(obj.finalize(), "", false) << "\n";
*/
	
	std::ifstream input_file (".testdata.bin", std::ios::in|std::ios::binary|std::ios::ate);
	if (input_file.is_open()) {
	    const size_t rate_in_bytes = 136;     // in bytes
	    std::string buffer(rate_in_bytes+1, 0);

	    size_t left_to_read = input_file.tellg();
        input_file.seekg (0, std::ios::beg);
	    while(left_to_read) {
	        size_t block_size = std::min(left_to_read, rate_in_bytes);
	        input_file.read(&buffer.front(), block_size);
	        left_to_read -= block_size;

	        obj.update(buffer.begin(), buffer.begin() + block_size);

	        std::cout << "Read " <<  block_size << " bytes"
	                  << "(" << left_to_read << " left)\n";
	        std::copy(buffer.begin(), buffer.begin()+block_size,
	                  std::ostream_iterator<char>(std::cout, ""));
	        std::cout << "\n";
	    }
        input_file.close();

        std::cout << "\nDigest of file:\n";
        std::cout << byte_vec_to_str(obj.finalize(), " ", true, 16) << "\n";
	}
	else {
	    std::cout << "Error opening file!\n";
	}
    

	std::cout << "\n-------------------\n" << "End.\n";

	return(0);
}

/*
  // ----------- Read from file (binary) --------------
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

  //------------ Reading an entire binary file --------------
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

