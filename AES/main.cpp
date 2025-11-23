#include <iostream>
#include <array>
#include <cstdint>
#include "common/helpers.h"
#include "AES/AES.h"



int main()
{
    block key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    block text = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };


    AES::AES128 e;
    block my_result = e.encrypt(text, key);
    block lib_result = lib_encrypt(text, key);

    std::cout << "Library Output: ";    
    std::cout << lib_result << std::endl;

    std::cout << "\n\nMy output: ";
    std::cout << my_result << std::endl;

   

    return 0;
}