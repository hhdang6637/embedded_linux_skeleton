/*
 * serviceOpenvpn.h
 *
 *  Created on: Aug 16, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_SERVICEOPENVPN_H_
#define APPLICATIONS_SYSTEM_MANAGER_SERVICEOPENVPN_H_

#include "service.h"

namespace app
{

class serviceOpenvpn: public service
{
private:
    serviceOpenvpn();

    static serviceOpenvpn* s_instance;

public:
    virtual ~serviceOpenvpn();
    virtual std::string service_name();
    virtual bool init();
    virtual bool start();

    static serviceOpenvpn* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_SERVICEOPENVPN_H_ */
