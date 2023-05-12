#ifndef WEBSOCKETSERVER_H
#define WEBSOCKETSERVER_H

#include <QObject>
#include <QWebSocketServer>
#include <QWebSocket>
#include <QThread>
#include <QList>

class WebSocketServer : public QObject
{
    Q_OBJECT

    QWebSocketServer *m_server = nullptr;
    QMap<QUuid, QWebSocket*> m_clients;
    QMap<QUuid, QPair<QString, QString>> m_requests;

    QString m_publicKey;
    QString m_privateKey;
    QString m_pkSignature;

    QThread *m_thread = nullptr;

public:
    explicit WebSocketServer(QObject *parent = nullptr);
    ~WebSocketServer();

    Q_INVOKABLE void createServer(quint16 portNumber);
    Q_INVOKABLE void destroyServer();

    bool validateSignature(const QString& data, const QString& signature, const QString& key);
private:
    QPair<QString, QString> parseLicenseCheckRequest(const QString& json);
    QString signData(const QString &dataString);

signals:
    void signalValidateLicense(QString appName, QString licenseKey);

private slots:

    void onNewConnection();
    void socketDisconnected();
    void onError();

    // slot for incoming message from client
    void receivedData(const QString& data);

public slots:
    void setKeys(const QString& publicKey, const QString& privateKey, const QString& publicKeySign);
    void sendValidatedLicense(bool valid, const QString& message, const QString& parameters, const QString& licenseKey, const QString& appName);
};

#endif // WEBSOCKETSERVER_H
