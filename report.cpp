#include "report.h"

#include <QJsonArray>

Report::Report()
{

}

void Report::fromJson(QJsonObject obj)
{
    if (obj.isEmpty()){
        return;
    }

    m_deviceId = obj.value("Id").toInt();
    m_heartbeatFrequency = obj.value("HeartbeatFrequency").toInt();
    m_serverTime = obj.value("ServerTime").toString();

    QJsonArray licenseArray = obj.value("Licenses").toArray();
    for (const auto& licenseObj : licenseArray){
        License l;
        l.fromJson(licenseObj.toObject());
        m_licenseList.append(l);
    }

    QJsonArray violationArray = obj.value("Violations").toArray();
    for (const auto& violationObj : violationArray){
        Violation v;
        v.fromJson(violationObj.toObject());
        m_violationList.append(v);
    }
}

QList<Violation> Report::getViolationList() const
{
    return m_violationList;
}

QList<License> Report::getLicenseList() const
{
    return m_licenseList;
}

int Report::getHeartbeatFrequency() const
{
    return m_heartbeatFrequency;
}

QString Report::getServerTime() const
{
    return m_serverTime;
}

int Report::getDeviceId() const
{
    return m_deviceId;
}
