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
#include <algorithm>
#include <fstream>

#include "resourceCollector.h"
#include "netlink_socket.h"
#include "conversion.h"

#define CPU_TEMP_THRESHOLD 40

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

cpu_stat_t resourceCollector::get_current_cpu()
{
    return this->cpu_history.back();
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

struct sysinfo resourceCollector::get_current_ram()
{
    return this->ram_history.back();
}

float resourceCollector::get_temperature()
{
    return this->temperature/1000;
}

std::list<struct rtnl_link_stats> resourceCollector::get_network_history(const std::string &if_name)
{
    std::map<std::string, std::list<struct rtnl_link_stats>>::iterator it = this->network_history.find(if_name);
    if (it != this->network_history.end())
        return this->network_history[if_name];

    return std::list<struct rtnl_link_stats>();
}

uint32_t resourceCollector::get_max_tx(const std::string &if_name)
{
    std::map<std::string, uint32_t>::iterator it = this->max_diff_tx.find(if_name);
    if (it != this->max_diff_tx.end())
        return this->max_diff_tx[if_name];

    return 0;
}

uint32_t resourceCollector::get_max_rx(const std::string &if_name)
{
    std::map<std::string, uint32_t>::iterator it = this->max_diff_rx.find(if_name);
    if (it != this->max_diff_rx.end())
        return this->max_diff_rx[if_name];

    return 0;
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
    std::list<struct net_interface_stats> stats;

    if (get_interfaces_stats(stats)) {
        auto append_to_network_history = [&](const struct net_interface_stats& info) {

            std::map<std::string, std::list<struct rtnl_link_stats>>::iterator it = this->network_history.find(info.if_name);
            uint32_t diff_tx = 0;
            uint32_t diff_rx = 0;
            struct rtnl_link_stats last;

            // non-existing element
            if (it == this->network_history.end()) {

                std::list<struct rtnl_link_stats> stats;
                stats.push_back(info.if_stats);
                this->network_history.insert(
                        std::pair<std::string, std::list<struct rtnl_link_stats>>(info.if_name, stats));

            } else {

                // insert to existing element. We need 61 samples to achieve to 60 rates
                if (this->network_history[info.if_name].size() >= resourceCollector::resource_history_max_sample + 1) {
                    this->network_history[info.if_name].pop_front();
                }

                last = this->network_history[info.if_name].back();
                diff_rx = info.if_stats.rx_bytes - last.rx_bytes;
                diff_tx = info.if_stats.tx_bytes - last.tx_bytes;

                this->network_history[info.if_name].push_back(info.if_stats);
            }

            std::map<std::string, uint32_t>::iterator max_diff_tx_it = this->max_diff_tx.find(info.if_name);
            if (max_diff_tx_it == this->max_diff_tx.end()) {
                this->max_diff_tx.insert(
                        std::pair<std::string, uint32_t>(info.if_name, diff_tx));
            } else {
                if (max_diff_tx_it->second < diff_tx) {
                    max_diff_tx_it->second = diff_tx;
                }
            }

            std::map<std::string, uint32_t>::iterator max_diff_rx_it = this->max_diff_rx.find(info.if_name);
            if (max_diff_rx_it == this->max_diff_rx.end()) {
                this->max_diff_rx.insert(
                        std::pair<std::string, uint32_t>(info.if_name, diff_rx));
            } else {
                if (max_diff_rx_it->second < diff_rx) {
                    max_diff_rx_it->second = diff_rx;
                }
            }
        };

        std::for_each(stats.cbegin(), stats.cend(), append_to_network_history);
    }
}

void resourceCollector::temperature_collect()
{
#if (defined pi_b_plus) || (defined pi_3_b)
    std::string temp_file = "/sys/class/thermal/thermal_zone0/temp";
#else
    std::string temp_file;
    syslog(LOG_ERR, "Device not support thermal management!!!");
    return;
#endif
    std::ifstream file(temp_file);
    if (file.is_open()) {
        file >> this->temperature;
        file.close();
    }

    if (this->temperature/1000 > CPU_TEMP_THRESHOLD)
        send_multicast_events(NETLINK_EVENTS_GROUP, EVENT_CPU_TEMP);
}

} /* namespace app */
