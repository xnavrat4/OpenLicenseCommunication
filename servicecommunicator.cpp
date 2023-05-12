#include "servicecommunicator.h"

#include <QJsonDocument>
#include <QJsonObject>
#include "botan/base64.h"
#include "botan/pubkey.h"
#include "botan/x509_key.h"
#include "licenseencrypter.h"
#include <botan/data_src.h>
#include <botan/pk_keys.h>

ServiceCommunicator::ServiceCommunicator(const QUrl &url, QObject *parent) :
    QObject(parent)
{
    qInfo() << "[INFO]\t[" << QDateTime::currentDateTime().toString(Qt::ISODate)
            << "Service communicator: Connecting to " << url;
    connect(&m_webSocket, &QWebSocket::connected, this, &ServiceCommunicator::onConnected);
    connect(&m_webSocket, &QWebSocket::disconnected, this, [this] {emit signalError("Service disconnected");});
    m_webSocket.open(QUrl(url));
}

QString ServiceCommunicator::createRequestJson(const QString &appName, const QString &licenseKey)
{
    QJsonObject obj;
    obj.insert("appName", appName);
    obj.insert("licenseKey", licenseKey);

    QString message = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    return message;
}

void ServiceCommunicator::onConnected()
{
    qInfo() << "[INFO]\t[" << QDateTime::currentDateTime().toString(Qt::ISODate)
            << "] Service communicator:  connected to WS server";
    connect(&m_webSocket, &QWebSocket::textMessageReceived, this, &ServiceCommunicator::onTextMessageReceived);
}

bool ServiceCommunicator::verifyLicenseObject(QJsonObject obj, const QString &publicKeyString, QJsonObject licenseObj)
{
    std::string signatureString = QByteArray::fromBase64(obj.value("licenseSig").toString().toUtf8()).toStdString();
    std::vector<uint8_t> signatureVector(signatureString.begin(), signatureString.end());

    std::string licenseString = QJsonDocument(licenseObj).toJson(QJsonDocument::Compact).toStdString();

    Botan::DataSource_Memory source(Botan::base64_decode(publicKeyString.toStdString()));
    std::unique_ptr<Botan::Public_Key> pbk(Botan::X509::load_key(source));

    Botan::PK_Verifier verifier(*pbk, "EMSA3(SHA-256)");
    verifier.update(licenseString);
    return verifier.check_signature(signatureVector);
}

bool ServiceCommunicator::verifyServiceKey(const QString &publicKeyString, const QString &pkSignature)
{
    std::string signatureString =  QByteArray::fromBase64(pkSignature.toUtf8()).toStdString();
    std::vector<uint8_t> signatureVector(signatureString.begin(), signatureString.end());

    Botan::DataSource_Memory source1(Botan::base64_decode(std::string(m_serverPublicKey)));
    std::unique_ptr<Botan::Public_Key> serverPublicKey(Botan::X509::load_key(source1));

    Botan::SecureVector<uint8_t> serviceKeyVector(Botan::base64_decode(publicKeyString.toStdString()));
    std::unique_ptr<Botan::Public_Key> servicePublicKey(Botan::X509::load_key(std::vector(serviceKeyVector.begin(), serviceKeyVector.end())));

    auto pbkBits = servicePublicKey->public_key_bits();

    auto qb= QByteArray(reinterpret_cast<char*>(pbkBits.data()), pbkBits.size()).toBase64();
    std::string dataString = QByteArray::fromBase64(qb).toStdString();

    Botan::PK_Verifier verifier(*serverPublicKey, "EMSA3(SHA-256)");
    verifier.update(dataString);
    return verifier.check_signature(signatureVector);
}

void ServiceCommunicator::onTextMessageReceived(const QString &message)
{
    QJsonDocument d = QJsonDocument::fromJson(message.toUtf8());
    QJsonObject object = d.object();
    quint32 random = object.value("random").toString().toDouble();
    QString encrypted = object.value("secret").toString();

    auto decrypted = LicenseEncrypter::decrypt(encrypted.toStdString(), random);
    decrypted.chop(decrypted.size() - decrypted.lastIndexOf("}") - 1);
    //TODO:delete trailing chars
    auto doc = QJsonDocument::fromJson(decrypted.toUtf8());
    QJsonObject obj = doc.object();

    QJsonObject licenseObj = obj.value("license").toObject();
    QString publicKeyString = obj.value("publicKey").toString();
    QString pkSignature = obj.value("pkSignature").toString();

    //verify license signature
    if (!verifyLicenseObject(obj, publicKeyString, licenseObj)){
        emit signalError("License verification failed");
        return;
    }
    if(!verifyServiceKey(publicKeyString, pkSignature)){
        emit signalError("Server verification failed");
        return;
    }

    bool valid = licenseObj.value("valid").toBool(false);
    QString msg = licenseObj.value("message").toString();
    QString params = licenseObj.value("params").toString();

    emit signalLicenseValidated(valid, params, msg);
}

void ServiceCommunicator::sendValidate(const QString &appName, const QString &licenseKey)
{
    QString message = createRequestJson(appName, licenseKey);
    if (m_webSocket.isValid()){
        m_webSocket.sendTextMessage(message);
    }else {
        qInfo() << "[ERROR]\t[" << QDateTime::currentDateTime().toString(Qt::ISODate)
                << "] Service communicator:  Socket is not ready";
        QMetaObject::Connection * const connection = new QMetaObject::Connection;
        *connection = connect(&m_webSocket, &QWebSocket::connected, this, [this, connection, message]{
            m_webSocket.sendTextMessage(message);
            QObject::disconnect(*connection);
            delete connection;
        });
    }
}
