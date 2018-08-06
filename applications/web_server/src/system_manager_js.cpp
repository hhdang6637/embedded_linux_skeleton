/*
 * system_manager_js.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include <string>
#include <sstream>
#include <stdlib.h>
#include <list>          // std::queue

#include "simplewebfactory.h"
#include "rpcUnixClient.h"
#include "rpcMessageResourceHistory.h"

std::string json_resource_usage_history(FCGX_Request *request)
{
    std::ostringstream ss_json;
    ss_json << "{";

    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageResourceHistory msg;
    if (rpcClient->doRpc(&msg)) {

        cpu_stat_t pre, cur;
        std::list<cpu_stat_t> cpu_usage_history = msg.get_cpu_history();

        ss_json << "\"json_cpu_usage_history\":[";

        size_t counter = 0;
        for(std::list<cpu_stat_t>::iterator it = cpu_usage_history.begin();
                it != cpu_usage_history.end(); ++it) {

            counter++;

            if (it == cpu_usage_history.begin()) {
                pre = *it;
                continue;
            }

            cur = *it;

            long double total_diff = cur.total - pre.total;
            long double busy_diff = cur.busy - pre.busy;

            ss_json << (long)(busy_diff / total_diff * 100);

            if (counter < cpu_usage_history.size()) {
                ss_json << ",";
            }

            pre = cur;
        }

        ss_json << "]";

        std::list<struct sysinfo> ram_history = msg.get_ram_history();
        ss_json << ",\"json_ram_history\":[";

        counter = 0;
        for (std::list<struct sysinfo>::iterator it = ram_history.begin();
                it != ram_history.end(); ++it) {

            counter++;

            ss_json << (long)(it->totalram - it->freeram)*100/it->totalram;

            if (counter < ram_history.size()) {
                ss_json << ",";
            }
        }
        ss_json << "]";

//        std::list<struct net_device_stats> network_history = msg.get_network_history();
//
//        for (auto const& stats : network_history) {
//            //TODO
//        }
    }

    ss_json << "}";

    return ss_json.str();
}
