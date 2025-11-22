#pragma once

#include <cryptopp/aes.h>
#include <cryptopp/modes.h> 
#include <cryptopp/filters.h> 
#include <iomanip>
#include <iostream>

using block = std::array<uint8_t, 16>;

block lib_encrypt(const block& plaintext, const block& key) {
    block ciphertext;
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;

    e.SetKey(key.data(), key.size());
    e.ProcessData(ciphertext.data(), plaintext.data(), plaintext.size());

    return ciphertext;
}

std::ostream& operator<<(std::ostream& stream, const block& data)
{
    std::ios_base::fmtflags f(stream.flags());

    stream << std::hex << std::uppercase << std::setfill('0');

    for (auto& elem : data)
    {
        stream << std::setw(2) << static_cast<int>(elem) << " ";
    }

    stream.flags(f);
    return stream;
}