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
#include "rpcMessageResourceHistory.h"

namespace app {

class resourceCollector {
private:
    resourceCollector();
    static resourceCollector* s_instance;

    std::list<cpu_stat_t>                                     cpu_history;
    std::list<struct sysinfo>                                 ram_history;
    std::map<std::string, std::list<struct rtnl_link_stats>>  network_history;
    std::map<std::string, uint32_t>                           max_diff_tx;
    std::map<std::string, uint32_t>                           max_diff_rx;
    float                                                     temperature;
public:
    virtual ~resourceCollector();

    std::list<cpu_stat_t>              get_cpu_history();
    cpu_stat_t                         get_current_cpu();
    std::list<struct sysinfo>          get_ram_history();
    struct sysinfo                     get_current_ram();
    float                              get_temperature();
    std::list<struct rtnl_link_stats>  get_network_history(const std::string &if_name);
    uint32_t                           get_max_tx(const std::string &if_name);
    uint32_t                           get_max_rx(const std::string &if_name);

    void cpu_do_collect();
    void ram_do_collect();
    void network_do_collect();
    void temperature_collect();

    static resourceCollector* getInstance();
    static const int resource_history_max_sample = 61;
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_ */
