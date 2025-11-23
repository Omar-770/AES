#pragma once

#include <cryptopp/aes.h>
#include <cryptopp/modes.h> 
#include <cryptopp/filters.h> 
#include <cstdint>
#include <array>
#include "common/constants.h"

namespace AES
{
	class AES128;

	using block128 = std::array<uint8_t, 16>;
	using row128 = std::array<uint8_t, 4>;
	using col128 = std::array<uint8_t, 4>;
	using word = std::array<uint8_t, 4>;
		

	class AES128
	{
	public:

		block128 encrypt(const block128& plaintext, const block128& key);

	private:
		void sub_bytes(block128& state);
		void sub_bytes(word& word);
		void shift_rows(block128& state);
		void shift_row(row128& r, size_t shift); //helper
		void mix_columns(block128& state);
		uint8_t multiply_g(uint8_t x, uint8_t y); //helper
		void add_round_key(block128& state, const block128& key);
		std::array<block128, 11> expand_key(const block128& key);
	};
}