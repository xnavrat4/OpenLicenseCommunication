#ifndef LICENSE_H
#define LICENSE_H

#include <QString>
#include <QDateTime>
#include <QJsonObject>


class License
{
    int m_id{0};
    QString m_licenseKey;
    QString m_productName;
    QString m_parameters;
    bool m_revoked{false};
    QDateTime m_validFrom;
    QDateTime m_validTo;

public:
    License();

    bool operator ==(const License& other) const;
    bool operator !=(const License& other) const;

    void fromJson(QJsonObject obj);
    QJsonObject toJson();

    QString getSerialNumber() const;
    QString getParameters() const;
    QString getProductName() const;
    QDateTime getValidFrom() const;
    QDateTime getValidTo() const;
    bool getRevoked() const;
};

#endif // LICENSE_H
