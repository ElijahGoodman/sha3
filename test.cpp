/* 
 * main.cpp
 * 2022 Copyright © by Elijah Coleman
 */
//-----------------------------------------------------------------------------

#include <iostream>
#include <bit>		// !!! C++20 required
#include <bitset>

//-----------------------------------------------------------------------------
using my_int = uint16_t;

//-----------------------------------------------------------------------------
// bit masks
enum {
	zero_bit 	= 1,
	fourth_bit 	= 0b10000,
	fifth_bit 	= 0b100000,
	sixth_bit	= 0b1000000,
	eighth_bit	= 0b100000000,
	trunc_8bit 	= 0b11111111
};

//-----------------------------------------------------------------------------
// FUNCTIONS
//-----------------------------------------------------------------------------
inline void set_bit(my_int* number, my_int bit)
{
	*number |= bit;
}

//-----------------------------------------------
inline void reset_bit(my_int* number, my_int bit)
{
	*number &= ~bit;
}

//-----------------
my_int rc(my_int t)
{
	my_int R = 0b10000000;
	std::cout << std::hex << R << " | " << std::bitset<8>(R) << '\n';

	for(my_int i=1; i <= t; i++) {
		R = R << 1;		// equivalent R = 0 || R;

		my_int 	R8 = R & eighth_bit,
				R0 = R & zero_bit, R4 = R & fourth_bit,
				R5 = R & fifth_bit, R6 = R & sixth_bit;

		R8 >>= 2;
		if(R6 xor R8)	R |= sixth_bit;		// R[6] = R[6] XOR R[8]
		else			R &= ~sixth_bit;

		R8 >>= 1;
		if(R5 xor R8)	R |= fifth_bit;		// R[5] = R[5] XOR R[8]
		else			R &= ~fifth_bit;

		R8 >>= 1;
		if(R4 xor R8)	R |= fourth_bit;	// R[4] = R[4] XOR R[8]
		else			R &= ~fourth_bit;

		R8 >>= 4;
		if(R0 xor R8)	R |= zero_bit;		// R[0] = R[0] XOR R[8]
		else			R &= ~zero_bit;

		R = R & trunc_8bit;		// equivalent Trunc(8)[R]

		std::cout << std::hex << R << " | " << std::bitset<8>(R) << '\n';
	}

	return (R & zero_bit);
}

//----------------------------------
my_int round_constant(my_int rnd_index)
{
	unsigned long long RC(0);


}



//-----------------------------------------------------------------------------
int main(int, char**)
{
	/*
	// endianness testing: legacy version
	{
		unsigned short x = 1;	// 0x0001
		std::string endianness =
			((unsigned char*)&x) == 0 ? "big-endian\n" : "little-endian\n";
		std::cout << endianness;
	}

	// endianness testing: modern version (C++20 required) !!!
	if constexpr (std::endian::native == std::endian::big)
		std::cout << "big-endian\n";
	else if constexpr (std::endian::native == std::endian::little)
		std::cout << "little-endian\n";
	else
		std::cout << "mixed-endian\n";
	*/

	my_int t = 8;
	my_int res = rc(t);

	std::cout << "Result: rc(" << t << ") = " << res << '\n';
	std::cout << "----------------------\n";

	my_int l = 24;
	for(int j = 0; j < l; j++) {



	}


	return(0);
}



