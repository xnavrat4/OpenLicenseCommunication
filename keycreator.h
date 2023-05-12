#ifndef KEYCREATOR_H
#define KEYCREATOR_H

#include <QList>
#include <string>

class KeyCreator
{
public:
    KeyCreator();

    static std::string generateKeyAndIV(quint32 rand);
    static std::string generateKeyAndIV(QString hw);
};

#endif // KEYCREATOR_H
