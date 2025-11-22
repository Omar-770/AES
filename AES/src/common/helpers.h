#pragma once

#include <cryptopp/aes.h>
#include <cryptopp/modes.h> 
#include <cryptopp/filters.h> 

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
    stream.setf(std::ios_base::showbase | std::ios_base::hex);
    for (auto& elem : data)
    {
        stream << elem;
    }

    return stream;
}