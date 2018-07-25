/*
 * services.h
 *
 *  Created on: Jul 22, 2018
 *      Author: hhdang
 */

#ifndef _SERVICES_H_
#define _SERVICES_H_

#include <string>

namespace app
{
class service {
public:
    service();
    virtual ~service();
    virtual std::string service_name() {return std::string("unknow");};
    virtual bool init() {return true;};
    virtual bool start() {return true;};
    virtual bool stop() {return true;};
};
} /* namespace app */

#endif /* _SERVICES_H_ */
