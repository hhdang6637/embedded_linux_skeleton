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

#include "cpu_stat.h"
#include "rpcMessage.h"
#include "netlink_socket.h"

namespace app
{
class rpcMessageResourceHistory: public rpcMessage
{
	std::list<cpu_stat_t>              cpu_history;
	std::list<struct sysinfo>          ram_history;
	std::list<struct rtnl_link_stats>  network_history;
	std::string                        interface_name; // used for get network statistics
public:
	virtual bool serialize(int fd);
	virtual bool deserialize(int);

    rpcMessageResourceHistory();
    virtual ~rpcMessageResourceHistory();
    std::list<cpu_stat_t>              get_cpu_history()     { return this->cpu_history;};
    std::list<struct sysinfo>          get_ram_history()     { return this->ram_history;};
    std::list<struct rtnl_link_stats>  get_network_history() { return this->network_history;}
    std::string                        get_interface_name()  { return this->interface_name;}

    void set_cpu_history    (std::list<cpu_stat_t> &cpu_history)                  { this->cpu_history = cpu_history; };
    void set_ram_history    (std::list<struct sysinfo> &ram_history)              { this->ram_history = ram_history; };
    void set_network_history(std::list<struct rtnl_link_stats> &network_history)  { this->network_history = network_history; };
    void set_interface_name (std::string &interface_name)                         { this->interface_name = interface_name; };
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_ */
