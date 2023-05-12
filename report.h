#ifndef REPORT_H
#define REPORT_H

#include "license.h"
#include "violation.h"

#include <QDateTime>



class Report
{
    int m_deviceId{0};
    QString m_serverTime;
    int m_heartbeatFrequency{0};
    QList<License> m_licenseList;
    QList<Violation> m_violationList;

public:
    Report();

    void fromJson(QJsonObject obj);

    int getDeviceId() const;
    QString getServerTime() const;
    int getHeartbeatFrequency() const;
    QList<License> getLicenseList() const;
    QList<Violation> getViolationList() const;
};

#endif // REPORT_H
