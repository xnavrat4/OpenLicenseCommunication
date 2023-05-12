#include "websocketserver.h"
#include "botan/base64.h"
#include "botan/x509_key.h"
#include "qjsondocument.h"
#include <QJsonObject>
#include <QtDebug>
#include <QRandomGenerator>

#include "licenseencrypter.h"
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

WebSocketServer::WebSocketServer(QObject *parent) :
    QObject(parent)
{
    m_thread = new QThread();
    moveToThread(m_thread);
    m_thread->start();
}

WebSocketServer::~WebSocketServer()
{
    QMetaObject::invokeMethod(this, "destroyServer");

    m_thread->quit();
    if(!m_thread->wait(1000)){
        m_thread->terminate();
    }
    delete m_thread;
    m_thread = nullptr;
}

void WebSocketServer::createServer(quint16 portNumber)
{
    if(m_server == nullptr){
        m_server = new QWebSocketServer(QStringLiteral("Open License service server"), QWebSocketServer::NonSecureMode, this);
    }

    if(m_server->listen(QHostAddress::Any, portNumber)) {
        qDebug() << "[ OK ]\t[" << QDateTime::currentDateTime().toString(Qt::ISODate)
                  << "] WebSocketServer: Started listening on port " << portNumber;
        connect(m_server, &QWebSocketServer::newConnection, this, &WebSocketServer::onNewConnection);
        connect(m_server, &QWebSocketServer::acceptError, this, &WebSocketServer::onError);
        connect(m_server, &QWebSocketServer::serverError, this, &WebSocketServer::onError);
    } else {
        qDebug() << "[ERROR]\t[" << QDateTime::currentDateTime().toString(Qt::ISODate)
                  << "] WebSocketServer: Cannot start listening on port " << portNumber
                  << " (error: "<< m_server->errorString() << ")";
    }
}

void WebSocketServer::destroyServer()
{
    qDeleteAll(m_clients);
    m_clients.clear();

    if(m_server != nullptr){
        m_server->close();
        delete m_server;
        m_server = nullptr;
    }
}

bool WebSocketServer::validateSignature(const QString &data, const QString &signature, const QString &key)
{
    std::string signatureString = QByteArray::fromBase64(signature.toUtf8()).toStdString();
    std::vector<uint8_t> signatureVector(signatureString.begin(), signatureString.end());

    std::string dataString = QByteArray::fromBase64(data.toUtf8()).toStdString();
    //std::vector<uint8_t> dataVector(dataString.begin(), dataString.end());

    Botan::SecureVector<uint8_t> keyVector(Botan::base64_decode(key.toStdString()));
    std::unique_ptr<Botan::Public_Key> pbk(Botan::X509::load_key(std::vector(keyVector.begin(), keyVector.end())));

    Botan::PK_Verifier verifier(*pbk, "EMSA3(SHA-256)");
    verifier.update(dataString);
    return verifier.check_signature(signatureVector);
}

QPair<QString, QString> WebSocketServer::parseLicenseCheckRequest(const QString &json)
{
    QPair<QString, QString> retVal;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());

    if (doc.isEmpty() || doc.isNull() || !doc.isObject()){
        return retVal;
    }

    QJsonObject obj = doc.object();
    QString appName = obj.value("appName").toString();
    QString licenseKey = obj.value("licenseKey").toString();
    retVal = {appName, licenseKey};
    return retVal;
}

QString WebSocketServer::signData(const QString& dataString)
{
    if (m_privateKey.isEmpty()){
        return QString();
    }

    Botan::AutoSeeded_RNG rng;
    Botan::DataSource_Memory source(Botan::base64_decode(m_privateKey.toStdString()));
    std::unique_ptr<Botan::Private_Key> privateKey(Botan::PKCS8::load_key(source));

    Botan::PK_Signer signer(*privateKey, rng, "EMSA3(SHA-256)");
    signer.update(dataString.toStdString());
    std::vector<uint8_t> signature = signer.signature(rng);

    return QByteArray(reinterpret_cast<const char*>(signature.data()), signature.size()).toBase64();
}

void WebSocketServer::onNewConnection()
{
    QWebSocket *client = m_server->nextPendingConnection();

    if(client == nullptr){
        return;
    }
    connect(client, &QWebSocket::textMessageReceived, this, &WebSocketServer::receivedData);
    connect(client, &QWebSocket::disconnected, this, &WebSocketServer::socketDisconnected);

    QUuid newQUuid = QUuid().createUuid();;
    m_clients.insert(newQUuid, client);

    qDebug() << "[INFO]\t[" << QDateTime::currentDateTime().toString(Qt::ISODate)
            << "] WebsocketServer: new client connected on port "
            << ", from address " << client->peerAddress().toString();
}

void WebSocketServer::socketDisconnected()
{
    QWebSocket *pClient = qobject_cast<QWebSocket *>(sender());
    if(pClient) {
        m_clients.remove(m_clients.key(pClient));
        pClient->deleteLater();
    }
}

void WebSocketServer::receivedData(const QString& data)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());

    auto clientId = m_clients.key(client);
    auto appAndLicense = parseLicenseCheckRequest(data);
    m_requests.insert(clientId, appAndLicense);
    emit signalValidateLicense(appAndLicense.first, appAndLicense.second);
}

void WebSocketServer::setKeys(const QString &publicKey, const QString &privateKey, const QString &publicKeySign)
{
    m_privateKey = privateKey;
    m_publicKey = publicKey;
    m_pkSignature = publicKeySign;
}

void WebSocketServer::sendValidatedLicense(bool valid, const QString &message, const QString &parameters, const QString &licenseKey, const QString &appName)
{
    QJsonObject obj;
    QJsonObject licenseObj;
    licenseObj.insert("valid", valid);
    licenseObj.insert("message", message);
    licenseObj.insert("params", parameters);

    obj.insert("license", licenseObj);
    obj.insert("licenseSig", signData(QJsonDocument(licenseObj).toJson(QJsonDocument::Compact)));
    obj.insert("publicKey", m_publicKey);
    obj.insert("pkSignature", m_pkSignature);


    quint32 value = QRandomGenerator::global()->generate();
    auto encryptedLicense = LicenseEncrypter::encrypt(QJsonDocument(obj).toJson(QJsonDocument::Compact), value);
    QJsonObject finalObj;
    finalObj.insert("random", QString::number(value));
    finalObj.insert("secret", QString::fromStdString(encryptedLicense));
    auto msg = QJsonDocument(finalObj).toJson(QJsonDocument::Compact);

    //send to all clients who requested it
    auto clients = m_requests.keys({appName, licenseKey});
    for (auto clientUuId : clients){
        auto client = m_clients.value(clientUuId);
        if (client){
            client->sendTextMessage(QString(msg));
        }
        m_requests.remove(clientUuId);
    }
}

void WebSocketServer::onError()
{
    qDebug() << "[ERROR]\t[" << QDateTime::currentDateTime().toString(Qt::ISODate)
            << "] WebsocketServer: port " << m_server->serverPort() << ", error " << m_server->errorString();
}
