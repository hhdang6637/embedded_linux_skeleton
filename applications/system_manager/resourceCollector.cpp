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

#include "resourceCollector.h"
#include "netlink_socket.h"

namespace app {

resourceCollector::resourceCollector()
{
    struct sockaddr_nl sa;

    if ((this->nl_fd = ::open_nl_socket()) == -1) {
        syslog(LOG_ERR, "open_nl_socket failed\n");
        exit(EXIT_FAILURE);
    }

    ::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    if (::bind_nl_socket(this->nl_fd, &sa, sizeof(sa)) == -1) {
        syslog(LOG_ERR, "bind_nl_socket failed\n");
        exit(EXIT_FAILURE);
    }
}

resourceCollector::~resourceCollector()
{
    ::close(this->nl_fd);
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

std::list<struct net_device_stats> resourceCollector::get_network_history()
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
    struct net_device_stats stats = { 0 };
    int                     if_index;
    struct sockaddr_nl      sa;
    static int              seq_number = 0;
    int                     nbytes;
    char                    buffer[4096];

    if_index = if_nametoindex("eth0"); //FIXME

    ::memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    if (::send_nl_get_request(this->nl_fd, if_index, &sa, sizeof(sa), ++seq_number) == -1) {
        syslog(LOG_ERR, "send_nl_get_request failed\n");
        return;
    }

    if ((nbytes = ::recv_nl_response(this->nl_fd, buffer, sizeof(buffer))) == -1) {
        syslog(LOG_ERR, "recv_nl_response failed\n");
        return;
    }

    ::parse_nl_data(buffer, nbytes, &stats);

    fprintf(stdout, "\t\treceive packets: %lu, bytes: %lu\n", stats.rx_packets, stats.rx_bytes);
    fprintf(stdout, "\t\tsend packets: %lu, bytes: %lu\n", stats.tx_packets, stats.tx_bytes);

    if (this->network_history.size() >= resourceCollector::resource_history_max_sample) {
        this->network_history.pop_front();
    }

    this->network_history.push_back(stats);
}

} /* namespace app */
