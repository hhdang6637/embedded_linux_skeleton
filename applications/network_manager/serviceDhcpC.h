/*
 * serviceDhcpC.h
 *
 *  Created on: Jul 27, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_NETWORK_MANAGER_SERVICEDHCPC_H_
#define APPLICATIONS_NETWORK_MANAGER_SERVICEDHCPC_H_

#include <list>
#include <string>
#include "service.h"

namespace app
{

class serviceDhcpC: public service
{
private:
    serviceDhcpC();
    pid_t dhcpClientPid;
    bool started;
    std::list<std::string> managedInterfaces;

    static serviceDhcpC* s_instance;
public:
    virtual ~serviceDhcpC();

    virtual std::string service_name();
    virtual bool init();
    virtual bool start();
    virtual bool stop();

    void addManagedInterfaces(std::string);

    static serviceDhcpC* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_NETWORK_MANAGER_SERVICEDHCPC_H_ */
