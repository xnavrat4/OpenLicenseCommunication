#ifndef SERVICECOMMUNICATOR_H
#define SERVICECOMMUNICATOR_H

#include <QObject>
#include <QtWebSockets/QWebSocket>
#include "obfuscate.h"

class ServiceCommunicator : public QObject
{
    Q_OBJECT

    QWebSocket m_webSocket;

    char* m_serverPublicKey = AY_OBFUSCATE("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs/BaWt+S/OYKHfgGotrG4T2y83katEW8qFvU3xFaSnzU1tSCiRlpN7O+PrjDPdLPMfUCuSCNhGsj6npnBjQiff9XEJHefOeJcLl5eINtA95aDsOVb6aDG4z1Bwbf0Wu6Q+xBfDyoio9mIngGJJTo9Mzpy8J7E4obdtphVTvsBG9fmkVqYBYaQicG88ZETjENd/EnLWB8vUSSKMCewJxJU09FJTWN3El9Et/DSPlHmzd1bvm3jpKK4o0wG4P5+1zXVyEWvSlks226G22PwTpnA88lLNzdS3af0np76djW6zGcaly3g0Ob8N5NizGX4C5mLGa0N1ZNgIpHYVgck+nsm9UNBn10Vb/OxDBa3gz5pCkp//nsOVnEI4sIjzT9tDfDs9MgbnaQwzKQt6oBNmFE24dwy3X1oqQFnPj5RDk23Muv25dq8Iscgdgm3i/S4k7UCk/HY4MrcaKEdZGTfQkVFSy9F2DsjORbSASOSox8M7+R6j6J+m6inSlaJsrjXBwd9nss5dhrBB+X49j+EGBrA8p08/P4SZs6WcvWjU07UibYi3z3D5ZA3X2yXg4VRAdYaz9EOs0l8JTC98intxVoc10ClBmbpEsuhrquxCfhvqs0cHbLGZnWfWOpiCBUiriIa+awb9cUZsIHU7IKXztTYEnMavIceIzdee6iYthsA7MCAwEAAQ==");

public:
    explicit ServiceCommunicator(const QUrl &url, QObject *parent = nullptr);

private:
    QString createRequestJson(const QString& appName, const QString& licenseKey);

    bool verifyLicenseObject(QJsonObject obj, const QString& publicKeyString, QJsonObject licenseObj);
    bool verifyServiceKey(const QString& publicKeyString, const QString& pkSignature);

public slots:
    void onConnected();
    void onTextMessageReceived(const QString& message);

    void sendValidate(const QString& appName, const QString& licenseKey);

signals:
    void signalLicenseValidated(bool valid, QString parameters, QString message = QString());
    void signalError(QString message);
};

#endif // SERVICECOMMUNICATOR_H
