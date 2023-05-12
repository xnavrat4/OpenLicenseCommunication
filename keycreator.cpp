#include "keycreator.h"
#include "obfy/instr.h"

#include <QRandomGenerator64>
#include <QCryptographicHash>


KeyCreator::KeyCreator()
{

}

std::string KeyCreator::generateKeyAndIV(quint32 rand)
{
    OBF_BEGIN;
    long a = N(6);
    int b = N(122);
    //assign rand into a
    V(a) = rand;
    size_t i =N(0);
    size_t j =N(0);
    quint32 value = QRandomGenerator::global()->generate64();
    V(value) =+ 5;
    long c = N(215646);
    //a is divided by 7
    V(a) /= 7;
    size_t max=N(2);
    size_t s = N(65);
    V(s) = N(6);
    //absolutely nothing
    V(value) |= 0xaaaaaaaa;
    //a is multiplied by 7
    V(a) *= 7;
    QByteArray ar;
    //set a to bytearray
    ar.setNum(V(a));
    //hash a
    QByteArray aaa = QCryptographicHash::hash(ar, QCryptographicHash::Sha512);
    V(s) = aaa.size();
    char t[128] = {};
    //take each byte and get hex value -> that is stored as chars
    FOR(V(i) = N(0), V(i) < V(s), V(i)++)
        char tsdf[2] = {};
        QByteArray b;
        b.append(static_cast<int>(aaa.at(V(i))));
        QString uf = b.toHex();
        FOR(V(j) = N(0), V(j) < V(max), V(j)++)
            V(tsdf[j]) = uf.at(V(j)).toLatin1();
        ENDFOR
        V(t[2*i]) = tsdf[N(0)];
        V(t[2*i + N(1)]) = tsdf[N(1)];
    ENDFOR
    long dsaf = aaa.toLong();
    //V(a) = QCryptographicHash::hash(ar, QCryptographicHash::Sha512).toULong();
    FOR(V(i) = N(0), V(i) < V(s), V(i)++)
        //V(t[i]) = static_cast<int>(aaa.at(V(i)));
    ENDFOR
    //get byte array from that hex value array ugliness
    QByteArray noat = QByteArray::fromRawData(t, N(128));
    //FOR(V(i) = N(0), V(i) < V(s), V(i)++)
    //    V(a) = V(a) << N(1);
    //    V(rand) = V(rand) >> N(4);
    //ENDFOR


    RETURN(noat.toStdString());

    OBF_END;
}

std::string KeyCreator::generateKeyAndIV(QString hw)
{
    OBF_BEGIN;

    size_t l = hw.length();
    //new container for hw
    char* ar = new char[l];
    size_t j =N(0);
    quint32 value = QRandomGenerator::global()->generate64();
    long k = N(42);
    V(k) = V(value);
    size_t ll = QString::number(V(k)).size();
    size_t max=N(2);
    char* arlulz = new char[ll];
    size_t i =N(0);

    FOR(V(i) = N(0), V(i) < V(l), V(i)++)
        ar[V(i)] = hw.at(V(i)).toLatin1();
    ENDFOR

    FOR(V(i) = N(0), V(i) < V(ll), V(i)++)
        arlulz[V(i)] = QString::number(V(k)).at(V(i)).toLatin1();
    ENDFOR

    int* heh = new int[l];

    FOR(V(i) = N(0), V(i) < V(l), V(i)++)
       heh[V(i)] = ar[V(i)] % 30;
    ENDFOR

    FOR(V(i) = N(0), V(i) < V(l), V(i)++)

    ENDFOR
    long a = N(6);
    int b = N(122);
    V(value) =+ 5;
    long c = N(215646);
    V(a) /= 7;
    size_t s = N(65);
    V(s) = N(6);

    V(value) |= 0xaaaaaaaa;

    QByteArray qar;
    qar.setRawData(ar, l);

    //V(a) = QCryptographicHash::hash(qar, QCryptographicHash::Sha512).toULong();

    //FOR(V(i) = N(0), V(i) < V(s), V(i)++)
    //    V(a) = V(a) << N(1);
    //    V(a) = V(a) >> N(4);
    //ENDFOR
    QByteArray aaa = QCryptographicHash::hash(qar, QCryptographicHash::Sha512);
    V(s) = aaa.size();
    char t[128] = {};
    //take each byte and get hex value -> that is stored as chars
    FOR(V(i) = N(0), V(i) < V(s), V(i)++)
            char tsdf[2] = {};
            QByteArray b;
            b.append(static_cast<int>(aaa.at(V(i))));
            QString uf = b.toHex();
            FOR(V(j) = N(0), V(j) < V(max), V(j)++)
                    V(tsdf[j]) = uf.at(V(j)).toLatin1();
            ENDFOR
            V(t[2*i]) = tsdf[N(0)];
            V(t[2*i + N(1)]) = tsdf[N(1)];
    ENDFOR
    long dsaf = aaa.toLong();
    //V(a) = QCryptographicHash::hash(ar, QCryptographicHash::Sha512).toULong();
    FOR(V(i) = N(0), V(i) < V(s), V(i)++)
            //V(t[i]) = static_cast<int>(aaa.at(V(i)));
    ENDFOR
    //get byte array from that hex value array ugliness
    QByteArray noat = QByteArray::fromRawData(t, N(128));

    RETURN(noat.toStdString());

    OBF_END;
}
