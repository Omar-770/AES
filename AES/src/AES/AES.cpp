#include "AES.h"

namespace AES
{
	void AES128::sub_bytes(block128& b)
	{
		for (auto& elem : b)
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
			for (int j = 0; j < cols[j].size(); j++)
			{
				uint8_t temp = 0;
				for (int k = 0; k < cols[j].size(); k++)
					temp ^= multiply_g(mix_matrix[j][k], cols[i][k]);
									
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
			uint8_t _2x = multiply_2(x);
			return _2x ^ x;
			break;

		default:
			throw(std::invalid_argument("AES128::multiply_g() cannot handle a second argument larger than 3"));
		}

		return x;
	}
}
