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
#include "rpcMessageCpuHistory.h"

std::string json_cpu_usage_history(const char*url)
{
    std::ostringstream ss_json;
    ss_json << "{\"json_cpu_usage_history\":[";

    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageCpuHistory msg;
    if (rpcClient->doRpc(&msg)) {

        cpu_stat_t pre, cur;
        std::list<cpu_stat_t> cpu_usage_history = msg.get_cpu_history();

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
    }

    ss_json << "]}";

    return ss_json.str();
}
