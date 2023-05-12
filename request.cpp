#include "request.h"
#include "qsslconfiguration.h"
#include "quuid.h"

Request::Request()
{
    setSSLConfig();
    setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
}

Request::Request(QUrl url, QUuid uuid)
{
    setSSLConfig();
    setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    setUrl(url);
    setAttribute(User, uuid);
    setTransferTimeout(5000);
}

void Request::setSSLConfig()
{
    QSslConfiguration sslConfig = sslConfiguration();
    sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    setSslConfiguration(sslConfig);
}
