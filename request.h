#ifndef REQUEST_H
#define REQUEST_H

#include <QNetworkRequest>

class Request : public QNetworkRequest
{
public:
    Request();
    Request(QUrl url, QUuid uuid);

    void setSSLConfig();
};

#endif // REQUEST_H
