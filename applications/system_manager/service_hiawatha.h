/*
 * service_hiawatha.h
 *
 *  Created on: Jul 22, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_SERVICE_HIAWATHA_H_
#define APPLICATIONS_SYSTEM_MANAGER_SERVICE_HIAWATHA_H_

#include "service.h"

class service_hiawatha: public service {

private:

    service_hiawatha();

    static service_hiawatha* s_instance;

public:
    virtual ~service_hiawatha();
    virtual std::string service_name();
    virtual bool init();
    virtual bool start();
//    virtual bool stop();

    static service_hiawatha* getInstance();
};

#endif /* APPLICATIONS_SYSTEM_MANAGER_SERVICE_HIAWATHA_H_ */
