#ifndef NETWORKCLIENT_H
#define NETWORKCLIENT_H

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QAuthenticator>
#include <QNetworkProxy>
#include <QJsonObject>

class NetworkClient : public QObject
{
    Q_OBJECT

    QNetworkAccessManager* m_netManager;

public:
    NetworkClient(QObject* parent = nullptr);

    QUuid sendGetAllRequest(QString url);
    QUuid sendGetRequest(QUrl url);
    QUuid sendPostRequest(QString url, QJsonObject jsonObj);
    QUuid sendPutRequest(QString url, QJsonObject jsonObj);

signals:
    void signalReply(QNetworkReply* reply);
};

#endif // NETWORKCLIENT_H
