/*
 * serviceDnsmasq.h
 *
 *  Created on: Aug 30, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_NETWORK_MANAGER_SERVICEDNSMASQ_H_
#define APPLICATIONS_NETWORK_MANAGER_SERVICEDNSMASQ_H_

#include "service.h"

namespace app
{

class serviceDnsmasq: public service
{
private:
    serviceDnsmasq();
    bool started;

    static serviceDnsmasq* s_instance;
public:
    virtual ~serviceDnsmasq();
    virtual std::string service_name();
    virtual bool init();
    virtual bool start();
    virtual bool stop();

    static serviceDnsmasq* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_NETWORK_MANAGER_SERVICEDNSMASQ_H_ */
