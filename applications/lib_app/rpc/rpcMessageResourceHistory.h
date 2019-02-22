/*
 * rpcMessageResourceHistory.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_

#include <list>
#include <map>
#include <sys/sysinfo.h>
#include <sys/time.h>

#include "cpu_stat.h"
#include "rpcMessage.h"
#include "netlink_socket.h"

#define MAX_DESC 128

namespace app
{
    typedef struct {
        cpu_stat_t     current_cpu;
        struct sysinfo current_ram;
        float          temperature; // expressed in degree Celsius
        char           fw_description[MAX_DESC];
        time_t         current_time;
    } resourceGeneralInfo_t;

    enum class rpcResourceActionType : uint16_t
    {
        GET_RESOURCE_HISTORY,
        GET_GENERAL_INFO
    };

class rpcMessageResourceHistory: public rpcMessage
{

    std::list<cpu_stat_t>              cpu_history;
    std::list<struct sysinfo>          ram_history;
    std::list<struct rtnl_link_stats>  network_history;
    uint32_t                           max_tx;
    uint32_t                           max_rx;
    std::string                        interface_name; // used for get network statistics
    resourceGeneralInfo_t              general_info;

    app::rpcResourceActionType         msgAction;
public:
    virtual bool serialize(int fd);
    virtual bool deserialize(int);

    rpcMessageResourceHistory();
    virtual ~rpcMessageResourceHistory();
    std::list<cpu_stat_t>              get_cpu_history() const     { return this->cpu_history;};
    std::list<struct sysinfo>          get_ram_history() const     { return this->ram_history;};
    std::list<struct rtnl_link_stats>  get_network_history() const { return this->network_history;}
    uint32_t                           get_max_tx()          const { return this->max_tx;}
    uint32_t                           get_max_rx()          const { return this->max_rx;}
    std::string                        get_interface_name() const  { return this->interface_name;}
    resourceGeneralInfo_t              get_general_info() const    { return this->general_info;};

    app::rpcResourceActionType getMsgAction() const                { return this->msgAction;};
    void                       setMsgAction(const app::rpcResourceActionType &action) { this->msgAction = action;};

    void set_cpu_history    (const std::list<cpu_stat_t> &cpu_history)                  { this->cpu_history = cpu_history; };
    void set_ram_history    (const std::list<struct sysinfo> &ram_history)              { this->ram_history = ram_history; };
    void set_network_history(const std::list<struct rtnl_link_stats> &network_history)  { this->network_history = network_history; };
    void set_max_tx         (uint32_t max_tx)                                           { this->max_tx = max_tx;};
    void set_max_rx         (uint32_t max_rx)                                           { this->max_rx = max_rx;};
    void set_interface_name (const std::string &interface_name)                         { this->interface_name = interface_name; };
    void set_general_info   (const resourceGeneralInfo_t &info)                         { this->general_info = info;};
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_ */
