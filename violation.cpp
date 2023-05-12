#include "violation.h"

Violation::Violation()
{

}

Violation::Violation(ViolationType type, const QString &formerValue, const QString &currentValue, QDateTime time) :
    m_type(type),
    m_formerValue(formerValue),
    m_currentValue(currentValue),
    m_time(time)
{

}

bool Violation::isFromServer()
{
    return m_fromServer;
}

QString Violation::violationTypeToString(ViolationType type)
{
    switch (type) {
    case SystemTimeViolation: {
        return "System time violation";
    }
    case ServerTimeViolation: {
        return "Server time violation";
    }
    case HWViolation: {
        return "Hardware integrity violation";
    }
    default:
        return QString();
    }
}

QString Violation::getViolationTypeString()
{
    return violationTypeToString(m_type);
}

QJsonObject Violation::toJson() const
{
    QJsonObject obj;
    obj.insert("ViolationType", m_type);
    obj.insert("FormerValue", m_formerValue);
    obj.insert("CurrentValue", m_currentValue);
    obj.insert("DateTime", m_time.toString(Qt::ISODate));
    return obj;
}

void Violation::fromJson(QJsonObject obj, bool isFromServer)
{
    m_type = static_cast<ViolationType>(obj.value("ViolationType").toInt());
    m_formerValue = obj.value("FormerValue").toString();
    m_currentValue = obj.value("CurrentValue").toString();
    m_time = QDateTime::fromString(obj.value("DateTime").toString(), Qt::ISODate);
    m_fromServer = isFromServer;
}
