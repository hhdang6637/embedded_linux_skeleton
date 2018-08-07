/*
 * rpcMessageResourceHistory.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_

#include <list>
#include <sys/sysinfo.h>

#include "cpu_stat.h"
#include "rpcMessage.h"
#include "netlink_socket.h"

namespace app
{

    typedef struct {
        unsigned long total_rx_bytes;
        unsigned long total_tx_bytes;
    } total_network_statistics_t;
class rpcMessageResourceHistory: public rpcMessage
{
	std::list<cpu_stat_t> cpu_history;
	std::list<struct sysinfo> ram_history;
	std::list<app::total_network_statistics_t> network_history;
public:
	virtual bool serialize(int fd);
	virtual bool deserialize(int);

    rpcMessageResourceHistory();
    virtual ~rpcMessageResourceHistory();
    std::list<cpu_stat_t> get_cpu_history(){return this->cpu_history;};
    std::list<struct sysinfo> get_ram_history() { return this->ram_history;};
    std::list<app::total_network_statistics_t> get_network_history() {return this->network_history;}

    void set_cpu_history(std::list<cpu_stat_t> &cpu_history) { this->cpu_history = cpu_history; };
    void set_ram_history(std::list<struct sysinfo> &ram_history) { this->ram_history = ram_history; };
    void set_network_history(std::list<app::total_network_statistics_t> &network_history) { this->network_history = network_history; };
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_ */
