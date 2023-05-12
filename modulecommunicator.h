#ifndef MODULECOMMUNICATOR_H
#define MODULECOMMUNICATOR_H

#include <QObject>

class ModuleCommunicator : public QObject
{
    Q_OBJECT
public:
    explicit ModuleCommunicator(QObject *parent = nullptr);

signals:

};

#endif // MODULECOMMUNICATOR_H
