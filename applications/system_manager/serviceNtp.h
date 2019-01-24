/*
 * serviceNtp.h
 *
 *  Created on: Aug 16, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_SERVICENTP_H_
#define APPLICATIONS_SYSTEM_MANAGER_SERVICENTP_H_

#include "service.h"
#include "rpcMessageTime.h"

namespace app
{

class serviceNtp: public service
{
private:
    serviceNtp();

    static serviceNtp* s_instance;

public:
    virtual ~serviceNtp();
    virtual std::string service_name();
    virtual bool init();
    virtual bool start();

    bool              setNtpCfg(const ntpConfig_t &cfg);
    ntpConfig_t const &getNtpCfg() const;

    static serviceNtp* getInstance();
    bool stop();
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_SERVICENTP_H_ */
