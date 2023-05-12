#include "fileencrypter.h"

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <iostream>
#include "keycreator.h"

std::string FileEncrypter::encrypt(const QString &textToEncrypt, const QString &hwInfo)
{
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);

    auto keyAndIV = KeyCreator::generateKeyAndIV(hwInfo);
    const std::string plaintext(textToEncrypt.toStdString());
    const std::string encText = keyAndIV.substr(0, 16);

    Botan::secure_vector<uint8_t> myText(encText.data(), encText.data()+encText.length());
    Botan::secure_vector<uint8_t> iv = myText;

    Botan::secure_vector<uint8_t> pt (plaintext.data(), plaintext.data()+plaintext.length());
    auto keyVector = keyAndIV.substr(16, 16);
    const std::vector<uint8_t> key(keyVector.begin(), keyVector.end());


    enc->set_key(key);

    enc->start(iv);
    enc->finish(pt);

    return Botan::hex_encode(pt);
}

QString FileEncrypter::decrypt(const std::string &textToDecode, const QString &hwInfo)
{
    if (textToDecode.empty()){
        return QString();
    }
    auto keyAndIV = KeyCreator::generateKeyAndIV(hwInfo);
    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION);
    std::string encordedText;
    const std::string encText = keyAndIV.substr(0, 16);

    Botan::secure_vector<uint8_t> myText(encText.data(), encText.data()+encText.length());
    Botan::secure_vector<uint8_t> iv = myText;
    auto keyVector = keyAndIV.substr(16, 16);
    const std::vector<uint8_t> key(keyVector.begin(), keyVector.end());

    encordedText = textToDecode;
    Botan::secure_vector<uint8_t> tmpPlainText(Botan::hex_decode_locked(encordedText));

    dec->set_key(key);
    dec->start(iv);
    dec->finish(tmpPlainText);

    return QString::fromStdString(reinterpret_cast<char*>(tmpPlainText.data()));
}
