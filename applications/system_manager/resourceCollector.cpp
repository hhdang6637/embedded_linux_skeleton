/*
 * resourceCollector.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include <syslog.h>
#include <string.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <list>

#include "resourceCollector.h"
#include "netlink_socket.h"

namespace app {

resourceCollector::resourceCollector()
{
    // TODO Auto-generated constructor stub
}

resourceCollector::~resourceCollector()
{
    // TODO Auto-generated destructor stub
}

resourceCollector *resourceCollector::s_instance = 0;

resourceCollector* resourceCollector::getInstance()
{
    if (s_instance == 0) {
        s_instance = new resourceCollector();
    }

    return s_instance;
}

std::list<cpu_stat_t> resourceCollector::get_cpu_history()
{
    return this->cpu_history;
}

void resourceCollector::cpu_do_collect()
{
    cpu_stat_t stat = { 0 };

    if (::get_cpu_stat(&stat) == true) {

        if (this->cpu_history.size() >= resourceCollector::resource_history_max_sample) {
            this->cpu_history.pop_front();
        }

        this->cpu_history.push_back(stat);
    }
}

std::list<struct sysinfo> resourceCollector::get_ram_history()
{
    return this->ram_history;
}

std::list<app::total_network_statistics_t> resourceCollector::get_network_history()
{
    return this->network_history;
}

void resourceCollector::ram_do_collect()
{
    struct sysinfo ram_stat = { 0 };

    if (::sysinfo(&ram_stat) == 0) {

        if (this->ram_history.size() >= resourceCollector::resource_history_max_sample) {
            this->ram_history.pop_front();
        }

        this->ram_history.push_back(ram_stat);
    }
}

void resourceCollector::network_do_collect()
{
    std::list<struct interface_info> info;

    if (get_network_stats(info)) {
        app::total_network_statistics_t total = {};
        for (auto const &i : info) {
            total.total_rx_bytes += i.if_stats.rx_bytes;
            total.total_tx_bytes += i.if_stats.tx_bytes;
        }

        if (this->network_history.size() >= resourceCollector::resource_history_max_sample) {
            this->network_history.pop_front();
        }

        this->network_history.push_back(total);
    }
}

} /* namespace app */
