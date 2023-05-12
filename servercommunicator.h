#ifndef SERVERCOMMUNICATOR_H
#define SERVERCOMMUNICATOR_H

#include "license.h"
#include "networkclient.h"
#include "report.h"
#include "obfuscate.h"

#include <QObject>

class ServerCommunicator : public QObject
{
    Q_OBJECT

    NetworkClient* m_reportNetworkClient{nullptr};
    NetworkClient* m_licenseNetworkClient{nullptr};

    QString m_hostname;
    int m_port;

    int m_deviceId;
    QString m_publicKey;
    QString m_privateKey;
    char* m_serverPublicKey = AY_OBFUSCATE("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs/BaWt+S/OYKHfgGotrG4T2y83katEW8qFvU3xFaSnzU1tSCiRlpN7O+PrjDPdLPMfUCuSCNhGsj6npnBjQiff9XEJHefOeJcLl5eINtA95aDsOVb6aDG4z1Bwbf0Wu6Q+xBfDyoio9mIngGJJTo9Mzpy8J7E4obdtphVTvsBG9fmkVqYBYaQicG88ZETjENd/EnLWB8vUSSKMCewJxJU09FJTWN3El9Et/DSPlHmzd1bvm3jpKK4o0wG4P5+1zXVyEWvSlks226G22PwTpnA88lLNzdS3af0np76djW6zGcaly3g0Ob8N5NizGX4C5mLGa0N1ZNgIpHYVgck+nsm9UNBn10Vb/OxDBa3gz5pCkp//nsOVnEI4sIjzT9tDfDs9MgbnaQwzKQt6oBNmFE24dwy3X1oqQFnPj5RDk23Muv25dq8Iscgdgm3i/S4k7UCk/HY4MrcaKEdZGTfQkVFSy9F2DsjORbSASOSox8M7+R6j6J+m6inSlaJsrjXBwd9nss5dhrBB+X49j+EGBrA8p08/P4SZs6WcvWjU07UibYi3z3D5ZA3X2yXg4VRAdYaz9EOs0l8JTC98intxVoc10ClBmbpEsuhrquxCfhvqs0cHbLGZnWfWOpiCBUiriIa+awb9cUZsIHU7IKXztTYEnMavIceIzdee6iYthsA7MCAwEAAQ==");

    QMultiMap<QString, QString> m_clientRequests;   //licenseKey, appName
    QMap<QString, QUuid> m_networkRequests;         //licenseKey, request uuid

    QThread* m_thread;

public:
    explicit ServerCommunicator(int deviceId, QObject *parent = nullptr);
    ~ServerCommunicator();
    void connectNetworkClient(const QString& hostname, ushort port);

    void setPublicKey(const QString &newPublicKey);
    void setPrivateKey(const QString &newPrivateKey);

private:
    void parseRegistrationSuccessful(QJsonDocument doc);
    void parseLicense(QJsonDocument doc, const QString& appName);
    void parseReport(QJsonDocument doc);
    QByteArray decrypt(const QByteArray &cypher);
    bool validateSignature(const QString& data, const QString& signature);

    QJsonObject encryptBody(QJsonObject obj);

    QString getPublicKeyBits();
    
public slots:
    void sendRegisterService(QJsonObject hwIdentifiers);
    void sendChallengeResponse(int deviceId, QString response);
    void sendReport(int deviceId, QList<Violation> newViolations);
    void sendGetLicenseRequest(const QString& appName, const QString& key);

signals:
    void sendRegisteredDevice();
    void signalRegistrationSuccesfull(int deviceId, QString signature, QString serverTime);
    void signalLicenseValidated(License licenses, QString appName);
    void signalLicenseCheckTimeout(QString appName, QString licenseKey);
    void signalReportReceived(Report report);
    void signalReportTimedOut();

public slots:
    void onChallengeReplyReceiced(QNetworkReply *reply);
    void onRegisterReplyReceived(QNetworkReply *reply);
    void onLicenseReplyReceived(QNetworkReply *reply);
    void onReportReplyReceived(QNetworkReply *reply);
};

#endif // SERVERCOMMUNICATOR_H
