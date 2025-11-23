#include "AES.h"

namespace AES
{
	block128 AES128::encrypt(const block128& plaintext, const block128& key)
	{
		//build the state
		block128 state = plaintext;

		//expand key
		std::array<block128, 11> keys = expand_key(key);

		//round 1
		add_round_key(state, keys[0]);

		//rounds 1 - 9

		for (int i = 1; i <= 9; i++)
		{
			sub_bytes(state);
			shift_rows(state);
			mix_columns(state);
			add_round_key(state, keys[i]);
		}

		//round 10

		sub_bytes(state);
		shift_rows(state);
		add_round_key(state, keys[10]);

		return state;
	}
	void AES128::sub_bytes(block128& b)
	{
		for (auto& elem : b)
			elem = SBOX[elem];
	}

	void AES128::sub_bytes(word& word)
	{
		for (auto& elem : word)
			elem = SBOX[elem];
	}

	void AES128::shift_rows(block128& b)
	{
		std::array<row128, 4> rows;
		for (int i = 0; i < rows.size(); i++)
		{
			for (int j = 0; j < rows[i].size(); j++)
				rows[i][j] = b[i + 4 * j];

			shift_row(rows[i], i);

			for (int j = 0; j < rows[i].size(); j++)
				b[i + 4 * j] = rows[i][j];

		}
	}

	void AES128::shift_row(row128& r, size_t shift)
	{
		auto temp = r;
		for (int i = 0; i < r.size(); i++)
			r[i] = temp[(i + shift) % r.size()];
	}

	void AES128::mix_columns(block128& b)
	{
		std::array<col128, 4> cols;
		
		std::array<row128, 4> mix_matrix =
		{
			row128{2, 3, 1, 1},
			row128{1, 2, 3, 1},
			row128{1, 1, 2, 3},
			row128{3, 1, 1, 2}
		};

		for (int i = 0; i < cols.size(); i++)
			for (int j = 0; j < cols[i].size(); j++)
				cols[i][j] = b[4 * i + j];

		for (int i = 0; i < cols.size(); i++)
			for (int j = 0; j < cols[i].size(); j++)
			{
				uint8_t temp = 0;
				for (int k = 0; k < cols[j].size(); k++)
					temp ^= multiply_g(cols[i][k], mix_matrix[j][k]);
				
				b[4 * i + j] = temp;
			}
	}

	uint8_t AES128::multiply_g(uint8_t x, uint8_t y)
	{
		auto multiply_2 = [](uint8_t x) -> uint8_t
		{
			if (x & 0b1000'0000)
			{
				x <<= 1;
				x ^= 0x1B;
			} 
			else
				 x <<= 1;

			return x;
		};

		uint8_t _2x{};
		switch (y)
		{
		case 0:
			return 0;
			break;

		case 1:
			return x;
			break;

		case 2:
			return multiply_2(x);			
			break;

		case 3:
			_2x = multiply_2(x);
			return _2x ^ x;
			break;

		default:
			throw(std::invalid_argument("AES128::multiply_g() cannot handle a second argument larger than 3"));
		}

		return x;
	}

	void AES128::add_round_key(block128& state, const block128& key)
	{
		for (int i = 0; i < state.size(); i++)
			state[i] ^= key[i];
	}

	std::array<block128, 11> AES128::expand_key(const block128& key)
	{
		std::array<word, 44> words;
		for (int i = 0; i < 4; i++)
			for(int j = 0; j < 4; j++)
				words[i][j] = key[4 * i + j];

		word temp;
		for (int i = 4; i < 44; i++)
		{
			temp = words[i - 1];
			if (i % 4 == 0)
			{
				shift_row(temp, 1);
				sub_bytes(temp);
				temp[0] ^= RCON[i / 4];
			}

			for(int j = 0; j < 4; j++)
				words[i][j] = words[i - 4][j] ^ temp[j];
		}

		std::array<block128, 11> expanded_key;
		for (int i = 0; i < 11; i++)
			for (int j = 0; j < 4; j++)
				for (int k = 0; k < 4; k++)
					expanded_key[i][4 * j + k] = words[4 * i + j][k];

		return expanded_key;
	}
}
