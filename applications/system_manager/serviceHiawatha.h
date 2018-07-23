/*
 * service_hiawatha.h
 *
 *  Created on: Jul 22, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_SERVICEHIAWATHA_H_
#define APPLICATIONS_SYSTEM_MANAGER_SERVICEHIAWATHA_H_

#include "service.h"

namespace app
{
class serviceHiawatha: public service {

private:

    serviceHiawatha();

    static serviceHiawatha* s_instance;

public:
    virtual ~serviceHiawatha();
    virtual std::string service_name();
    virtual bool init();
    virtual bool start();
//    virtual bool stop();

    static serviceHiawatha* getInstance();
};
} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_SERVICEHIAWATHA_H_ */
