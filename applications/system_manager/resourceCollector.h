/*
 * resourceCollector.h
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_
#define APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_

#include <list>
#include <sys/sysinfo.h>

#include "cpu_stat.h"
#include "netlink_socket.h"

namespace app {

class resourceCollector {
private:
    resourceCollector();
    static resourceCollector* s_instance;

    std::list<cpu_stat_t> cpu_history;
    std::list<struct sysinfo> ram_history;
    std::list<struct net_device_stats> network_history;

    int nl_fd;
public:
    virtual ~resourceCollector();

    std::list<cpu_stat_t> get_cpu_history();
    std::list<struct sysinfo> get_ram_history();
    std::list<struct net_device_stats> get_network_history();

    void cpu_do_collect();
    void ram_do_collect();
    void network_do_collect();

    static resourceCollector* getInstance();
    static const int resource_history_max_sample = 61;
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_ */
