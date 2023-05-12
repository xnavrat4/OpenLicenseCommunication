#ifndef VIOLATION_H
#define VIOLATION_H

#include <QJsonObject>
#include <QString>



class Violation
{
public:
    enum ViolationType {
        SystemTimeViolation = 1,
        ServerTimeViolation,
        HWViolation
    };

private:
    ViolationType m_type;
    QString m_formerValue;
    QString m_currentValue;
    QDateTime m_time;

    bool m_fromServer = false;

public:
    Violation();

    Violation(ViolationType m_type, const QString& m_formerValue, const QString& m_currentValue, QDateTime m_time);

    bool isFromServer();
    QString violationTypeToString(ViolationType type);
    QString getViolationTypeString();

    QJsonObject toJson() const;
    void fromJson(QJsonObject obj, bool isFromServer = true);
};

#endif // VIOLATION_H
