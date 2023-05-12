#include "botan/base64.h"
#include "qjsonarray.h"
#include "servercommunicator.h"
#include "report.h"
#include "keycreator.h"

#include <QJsonDocument>
#include <QThread>
#include <QUrlQuery>

#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>
#include <botan/data_src.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/cipher_mode.h>

ServerCommunicator::ServerCommunicator(int deviceId, QObject *parent) :
    QObject{parent},
    m_deviceId(deviceId)
{
    m_reportNetworkClient = new NetworkClient(this);
    if (m_deviceId > 0){
        //service is registered
        connect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onReportReplyReceived);
    }else{
        //service is not registered and will need to pass server challenge
        connect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onChallengeReplyReceiced);
    }
    m_licenseNetworkClient = new NetworkClient(this);
    connect(m_licenseNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onLicenseReplyReceived);

    m_thread = new QThread();
    moveToThread(m_thread);
    m_thread->start();
}

ServerCommunicator::~ServerCommunicator()
{
    m_thread->quit();
    if(!m_thread->wait(1000)){
        m_thread->terminate();
    }
    delete m_thread;
    m_thread = nullptr;
}

void ServerCommunicator::connectNetworkClient(const QString &hostname, ushort port)
{
    m_hostname = hostname;
    m_port = port;
}

void ServerCommunicator::parseRegistrationSuccessful(QJsonDocument doc)
{
    QJsonObject obj;
    //return if invalid json
    if (doc.isNull() || !doc.isObject()){
        return;
    }

    obj = doc.object();
    QString pk = obj.value("publicKey").toString();
    QString signature = obj.value("signature").toString();
    QString serverTime = obj.value("dateTime").toString();

    if (validateSignature(pk, signature)){
        emit signalRegistrationSuccesfull(m_deviceId, signature, serverTime);
        disconnect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onChallengeReplyReceiced);
        connect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onReportReplyReceived);
    }
}

void ServerCommunicator::parseLicense(QJsonDocument doc, const QString &appName)
{
    if (doc.isEmpty() || doc.isNull() || !doc.isObject()){
        return;
    }

    License license;
    license.fromJson(doc.object());
    emit signalLicenseValidated(license, appName);
}

void ServerCommunicator::parseReport(QJsonDocument doc)
{
    if (doc.isEmpty() || doc.isNull() || !doc.isObject()){
        return;
    }

    QJsonObject reportObj = doc.object();
    Report r;
    r.fromJson(reportObj);
    emit signalReportReceived(r);
}

QByteArray ServerCommunicator::decrypt(const QByteArray &cypher)
{
    auto doc = QJsonDocument::fromJson(cypher);

    if (doc.isEmpty() || doc.isNull() || !doc.isObject()){
        return QByteArray();
    }

    QJsonObject obj = doc.object();
    QByteArray keyAndIV = QByteArray::fromBase64(obj.value("Key").toString().toUtf8());
    QByteArray data = QByteArray::fromBase64(obj.value("Secret").toString().toUtf8());

    try{
        Botan::AutoSeeded_RNG rng;
        Botan::SecureVector<uint8_t> keyBytes1(Botan::base64_decode(m_privateKey.toStdString()));
        Botan::DataSource_Memory source(keyBytes1);
        std::unique_ptr<Botan::Private_Key> pvk(Botan::PKCS8::load_key(source));

        std::string dataString = keyAndIV.toStdString();
        std::vector<uint8_t> pt(dataString.begin(), dataString.end());

        Botan::PK_Decryptor_EME dec(*pvk, rng, "PKCS1v15");
        Botan::secure_vector<uint8_t> pt2 = dec.decrypt(pt);
        QByteArray keyAndIVPlain = QByteArray(reinterpret_cast<char*>(pt2.data()), pt2.size());

        const std::vector<uint8_t> keyBytes(keyAndIVPlain.begin(), keyAndIVPlain.begin() + 16);
        const std::vector<uint8_t> IV(keyAndIVPlain.begin()+ 16, keyAndIVPlain.end());

        Botan::secure_vector<uint8_t> tmpPlainText(data.begin(), data.end());
        auto s = tmpPlainText.size();

        std::unique_ptr<Botan::Cipher_Mode> decryptor = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION);
        decryptor->set_key(keyBytes);
        decryptor->start(IV);
        decryptor->finish(tmpPlainText);

        return QByteArray(reinterpret_cast<char*>(tmpPlainText.data()), tmpPlainText.size());

    } catch (...) {
    }
    return "";
}

bool ServerCommunicator::validateSignature(const QString &data, const QString &signature)
{
    std::string signatureString = QByteArray::fromBase64(signature.toUtf8()).toStdString();
    std::vector<uint8_t> signatureVector(signatureString.begin(), signatureString.end());

    Botan::SecureVector<uint8_t> keyVector(Botan::base64_decode(std::string(m_serverPublicKey)));
    std::unique_ptr<Botan::Public_Key> pbk(Botan::X509::load_key(std::vector(keyVector.begin(), keyVector.end())));

    std::string dataString = QByteArray::fromBase64(data.toUtf8()).toStdString();
    std::vector<uint8_t> dataBytes(dataString.begin(), dataString.end());

    Botan::PK_Verifier verifier(*pbk, "EMSA3(SHA-256)");
    verifier.update(dataBytes);
    return verifier.check_signature(signatureVector);
}

QJsonObject ServerCommunicator::encryptBody(QJsonObject obj)
{
    //get string from jsonObject
    QJsonDocument jsonDoc(obj);
    QByteArray dataArray = jsonDoc.toJson(QJsonDocument::Compact);
    auto dataString = dataArray.toBase64().toStdString();

    //create a symmetric key for encrytpion
    Botan::AutoSeeded_RNG rng;
    Botan::SymmetricKey key(rng, 16);
    Botan::InitializationVector iv(rng, 16);
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);

    //convert data from string to secure vector
    const std::string plaintext(dataString);
    Botan::secure_vector<uint8_t> pt (plaintext.data(), plaintext.data()+plaintext.length());

    //encrypt data!
    enc->set_key(key);
    enc->start(iv.bits_of());
    enc->finish(pt);
    auto keyInB64 = Botan::base64_encode(pt);

    //convert Key and IV bits to string
    auto keystring = key.bits_of() + iv.bits_of();
    std::vector<uint8_t> keyVector(keystring.begin(), keystring.end());

    //load public key
    Botan::SecureVector<uint8_t> keyBytes(Botan::base64_decode(std::string(m_serverPublicKey)));
    Botan::DataSource_Memory source(keyBytes);
    std::unique_ptr<Botan::Public_Key> pbk(Botan::X509::load_key(source));

    //encrypt the key!
    Botan::PK_Encryptor_EME encryptor(*pbk, rng, "PKCS1v15");
    std::vector<uint8_t> entryptedVector = encryptor.encrypt(keyVector, rng);
    QString encryptedKey = QByteArray(reinterpret_cast<char*>(entryptedVector.data()), entryptedVector.size()).toBase64();

    QJsonObject encObj;
    encObj.insert("secret", QString::fromStdString(keyInB64));
    encObj.insert("key", encryptedKey);

    return encObj;
}

QString ServerCommunicator::getPublicKeyBits()
{
    Botan::DataSource_Memory source(Botan::base64_decode(m_publicKey.toStdString()));
    std::unique_ptr<Botan::Public_Key> pbk(Botan::X509::load_key(source));
    auto pbkBits = pbk->public_key_bits();

    return QByteArray(reinterpret_cast<char*>(pbkBits.data()), pbkBits.size()).toBase64();
}

void ServerCommunicator::sendRegisterService(QJsonObject hwIdentifiers)
{
    QJsonObject obj;
    obj.insert("hwInfo", hwIdentifiers);
    obj.insert("publicKey", getPublicKeyBits());

    m_reportNetworkClient->sendPostRequest("https://"+ m_hostname + ":" + QString::number(m_port) + "/Device/Register", obj);
}

void ServerCommunicator::sendChallengeResponse(int deviceId, QString response)
{
    QJsonObject obj;
    obj.insert("deviceId", deviceId);
    obj.insert("response", response);
    disconnect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onChallengeReplyReceiced);
    connect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onRegisterReplyReceived);

    m_reportNetworkClient->sendPostRequest("https://"+ m_hostname + ":" + QString::number(m_port) + "/Device/Challenge", obj);
}

void ServerCommunicator::sendReport(int deviceId, QList<Violation> newViolations)
{
    QJsonObject obj;
    obj.insert("deviceId", deviceId);
    QJsonArray v;
    for (const auto &violation: newViolations){
        v.append(violation.toJson());
    }
    obj.insert("violations", v);

    m_reportNetworkClient->sendPostRequest("https://"+ m_hostname + ":" + QString::number(m_port) + QString("/Device/Report"), encryptBody(obj));
}

void ServerCommunicator::sendGetLicenseRequest(const QString &appName, const QString &key)
{
    QJsonObject obj;
    obj.insert("LicenseKey", key);
    obj.insert("DeviceId", m_deviceId);

    auto id = m_licenseNetworkClient->sendPutRequest("https://"+ m_hostname + ":" + QString::number(m_port) + "/License", encryptBody(obj));
    m_clientRequests.insert(key, appName);
    m_networkRequests.insert(key, id);
}

void ServerCommunicator::onChallengeReplyReceiced(QNetworkReply *reply)
{
    QByteArray response = reply->readAll();
    if (reply->error() != QNetworkReply::NoError || response.isEmpty()){
        return;
    }

    auto obj = QJsonDocument::fromJson(response).object();
    long random = obj.value("random").toInt();
    int deviceId = obj.value("deviceId").toInt();
    if (deviceId > 0){
        m_deviceId = deviceId;
    }else {
        return;
    }

    std::string a = KeyCreator::generateKeyAndIV(quint32(random));
    disconnect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onChallengeReplyReceiced);
    connect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onRegisterReplyReceived);
    sendChallengeResponse(m_deviceId, QString::fromStdString(a));
}

void ServerCommunicator::onRegisterReplyReceived(QNetworkReply *reply)
{
    QByteArray response = reply->readLine();

    if (reply->error() != QNetworkReply::NoError || response.isEmpty()){
        //try to verify again
        disconnect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onRegisterReplyReceived);
        connect(m_reportNetworkClient, &NetworkClient::signalReply, this, &ServerCommunicator::onChallengeReplyReceiced);
        return;
    }

    parseRegistrationSuccessful(QJsonDocument::fromJson(response));
}

void ServerCommunicator::onLicenseReplyReceived(QNetworkReply *reply)
{
    QByteArray response = reply->readAll();

    // find request info
    QUuid requestId = reply->request().attribute(QNetworkRequest::User).toUuid();
    QString licenseKey = m_networkRequests.key(requestId);
    auto appName = m_clientRequests.value(licenseKey);

    if (reply->error() == QNetworkReply::NoError){
        auto decrytpedMsg = decrypt(response);
        parseLicense(QJsonDocument::fromJson(decrytpedMsg), appName);

    }else {
        qDebug()<< reply->errorString();
        emit signalLicenseCheckTimeout(appName, licenseKey);
    }
}

void ServerCommunicator::onReportReplyReceived(QNetworkReply *reply)
{
    QByteArray response = reply->readAll();

    if (reply->error() == QNetworkReply::NoError){
        auto decryptedResponse = decrypt(response);
        parseReport(QJsonDocument::fromJson(decryptedResponse));
        return;
    }
    qDebug()<< reply->errorString();
    //if report request timed out -> just send info
    emit signalReportTimedOut();
}

void ServerCommunicator::setPublicKey(const QString &newPublicKey)
{
    m_publicKey = newPublicKey;
}

void ServerCommunicator::setPrivateKey(const QString &newPrivateKey)
{
    m_privateKey = newPrivateKey;
}
