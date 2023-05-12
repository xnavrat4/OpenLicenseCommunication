#include "licenseencrypter.h"

#include <QRandomGenerator>
#include <QString>
#include <QDebug>

#include "keycreator.h"

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/rng.h>

std::string LicenseEncrypter::encrypt(const QString &textToEncrypt, quint32 random)
{
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);

    std::string k = KeyCreator::generateKeyAndIV(random);
    const std::string plaintext(textToEncrypt.toStdString());
    const std::string encText = k.substr(0, 16);

    Botan::secure_vector<uint8_t> iv(encText.data(), encText.data()+encText.length());


    Botan::secure_vector<uint8_t> myText(encText.data(), encText.data()+encText.length());

    Botan::secure_vector<uint8_t> pt (plaintext.data(), plaintext.data()+plaintext.length());
    auto kl = k.substr(16, 16);
    const std::vector<uint8_t> key(kl.begin(), kl.end());


    enc->set_key(key);

    enc->start(iv);
    enc->finish(pt);

    return Botan::hex_encode(pt);
}

QString LicenseEncrypter::decrypt(const std::string& textToDecode, quint32 random)
{
    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION);
    std::string encordedText;

    std::string k = KeyCreator::generateKeyAndIV(random);
    const std::string encText = k.substr(0, 16);

    Botan::secure_vector<uint8_t> myText(encText.data(), encText.data()+encText.length());
    Botan::secure_vector<uint8_t> iv = myText;
    auto kl = k.substr(16, 16);
    const std::vector<uint8_t> key(kl.begin(), kl.end());

    encordedText = textToDecode;
    Botan::secure_vector<uint8_t> tmpPlainText(Botan::hex_decode_locked(encordedText));

    dec->set_key(key);
    dec->start(iv);
    dec->finish(tmpPlainText);

    std::string sName(reinterpret_cast<char*>(tmpPlainText.data()));
    return QString::fromStdString(sName);
}
