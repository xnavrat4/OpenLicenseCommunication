#include "networkclient.h"
#include "request.h"

#include <QJsonDocument>

NetworkClient::NetworkClient(QObject* parent):
    QObject(parent)
{
    m_netManager = new QNetworkAccessManager(this);
    connect(m_netManager, &QNetworkAccessManager::finished ,this, &NetworkClient::signalReply);
}

QUuid NetworkClient::sendGetAllRequest(QString url)
{
    auto quuid = QUuid().createUuid();
    Request r(url, quuid);
    m_netManager->get(r);
    return quuid;
}

QUuid NetworkClient::sendGetRequest(QUrl url)
{
    auto quuid = QUuid().createUuid();
    Request r(url, quuid);
    m_netManager->get(r);
    return quuid;
}

QUuid NetworkClient::sendPostRequest(QString url, QJsonObject jsonObj)
{
    QJsonDocument jsonDoc(jsonObj);
    QByteArray data = jsonDoc.toJson(QJsonDocument::Compact);
    auto quuid = QUuid().createUuid();
    Request r(url, quuid);
    m_netManager->post(r, data);
    return quuid;
}

QUuid NetworkClient::sendPutRequest(QString url, QJsonObject jsonObj)
{
    QJsonDocument jsonDoc(jsonObj);
    QByteArray data = jsonDoc.toJson(QJsonDocument::Compact);
    QUuid quuid = QUuid().createUuid();
    Request r(url, quuid);
    m_netManager->put(r, data);
    return quuid;
}
