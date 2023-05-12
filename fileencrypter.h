#ifndef FILEENCRYPTER_H
#define FILEENCRYPTER_H

#include <string>
#include <QString>

class FileEncrypter
{
public:
    static std::string encrypt(const QString& textToEncrypt, const QString& hwInfo);
    static QString decrypt(const std::string& textToDecode, const QString& hwInfo);
};

#endif // FILEENCRYPTER_H
