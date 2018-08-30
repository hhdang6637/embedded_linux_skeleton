/*
 * serviceHostapd.h
 *
 *  Created on: Aug 30, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_NETWORK_MANAGER_SERVICEHOSTAPD_H_
#define APPLICATIONS_NETWORK_MANAGER_SERVICEHOSTAPD_H_

#include "service.h"

namespace app
{

class serviceHostapd: public service
{
private:
    serviceHostapd();
    bool started;

    static serviceHostapd* s_instance;
public:
    virtual ~serviceHostapd();
    virtual std::string service_name();
    virtual bool init();
    virtual bool start();
    virtual bool stop();

    static serviceHostapd* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_NETWORK_MANAGER_SERVICEHOSTAPD_H_ */
