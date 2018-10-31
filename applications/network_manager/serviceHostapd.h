/*
 * serviceHostapd.h
 *
 *  Created on: Aug 30, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_NETWORK_MANAGER_SERVICEHOSTAPD_H_
#define APPLICATIONS_NETWORK_MANAGER_SERVICEHOSTAPD_H_

#include "service.h"
#include "rpcMessageWifiSetting.h"
#include "ini.h"
#include "unistd.h"

namespace app
{

class serviceHostapd: public service
{
private:
    serviceHostapd();
    bool started;
    app::rpcMessageWifiSettingData_t msgData;

    static serviceHostapd* s_instance;
public:
    virtual ~serviceHostapd();
    virtual std::string service_name();
    virtual bool init();
    virtual bool start();
    virtual bool stop();

    static serviceHostapd*               getInstance();
    bool                                 writeToFile();
    bool                                 initFromFile();
    void                                 setWifiSettingData(const app::rpcMessageWifiSettingData_t msg);
    app::rpcMessageWifiSettingData_t     getWifiSettingData() const;
    app::rpcMessageWifiSettingResultType validateMsgConfig(const app::rpcMessageWifiSettingData_t msgData) const;
};

} /* namespace app */

#endif /* APPLICATIONS_NETWORK_MANAGER_SERVICEHOSTAPD_H_ */
