#include "license.h"

License::License()
{
}

bool License::operator ==(const License &other) const
{
    return (m_id == other.m_id &&
            m_licenseKey == other.m_licenseKey &&
            m_productName == other.m_productName &&
            m_parameters == other.m_parameters &&
            m_revoked == other.m_revoked &&
            m_validFrom == other.m_validFrom &&
            m_validTo == other.m_validTo);
}

bool License::operator !=(const License &other) const
{
    return !(*this == other);
}

void License::fromJson(QJsonObject obj)
{
    m_id = obj.value("Id").toInt();
    m_licenseKey = obj.value("LicenseKey").toString();
    m_productName = obj.value("ProductName").toString();
    m_parameters = obj.value("Parameters").toString();
    m_revoked = obj.value("Revoked").toBool();
    m_validFrom = QDateTime::fromString(obj.value("ValidFrom").toString(), Qt::ISODate);
    m_validTo = QDateTime::fromString(obj.value("ValidTo").toString(), Qt::ISODate);
}

QJsonObject License::toJson()
{
    QJsonObject obj;
    obj.insert("Id", m_id);
    obj.insert("LicenseKey", m_licenseKey);
    obj.insert("ProductName", m_productName);
    obj.insert("Parameters", m_parameters);
    obj.insert("Revoked", m_revoked);
    obj.insert("ValidFrom", m_validFrom.toString(Qt::ISODate));
    obj.insert("ValidTo", m_validTo.toString(Qt::ISODate));
    return obj;
}

QString License::getSerialNumber() const
{
    return m_licenseKey;
}

QString License::getParameters() const
{
    return m_parameters;
}

QString License::getProductName() const
{
    return m_productName;
}

QDateTime License::getValidFrom() const
{
    return m_validFrom;
}

QDateTime License::getValidTo() const
{
    return m_validTo;
}

bool License::getRevoked() const
{
    return m_revoked;
}
