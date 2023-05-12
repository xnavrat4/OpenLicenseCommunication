#ifndef LICENSEENCRYPTER_H
#define LICENSEENCRYPTER_H

#include <QString>
#include <string>

class LicenseEncrypter
{
public:
    static std::string encrypt(const QString& textToEncrypt, quint32 random);
    static QString decrypt(const std::string& textToDecode, quint32 random);
};

#endif // LICENSEENCRYPTER_H
