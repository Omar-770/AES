#pragma once

#include <cryptopp/aes.h>
#include <cryptopp/modes.h> 
#include <cryptopp/filters.h> 
#include <cstdint>
#include <array>
#include "common/sbox.h"

namespace AES
{
	class AES128;

	using block128 = std::array<uint8_t, 16>;
	using row128 = std::array<uint8_t, 4>;
	using col128 = std::array<uint8_t, 4>;
		

	class AES128
	{
	public:
		void sub_bytes(block128& b);
		void shift_rows(block128& b);
		void shift_row(row128& r, size_t shift);
		void mix_columns(block128& b);
		uint8_t multiply_g(uint8_t x, uint8_t y);
	};
}