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

#define TO_KBIT(a) ((a * 8 ) / 1000)

typedef std::list<float> tx_rates_t;
typedef std::list<float> rx_rates_t;

static std::pair<tx_rates_t, rx_rates_t> calculate_rates(const std::list<struct rtnl_link_stats> &stats)
{
    tx_rates_t    tx_rates;
    rx_rates_t    rx_rates;
    unsigned long tx_bytes_old = stats.begin()->tx_bytes;
    unsigned long rx_bytes_old = stats.begin()->rx_bytes;

    for (auto it = stats.begin(); it != stats.end(); ++it) {
        // skip the first sample
        if (it == stats.begin())
            continue;

        float tx_rate = 0, rx_rate = 0;
        if (it->tx_bytes != 0 && (tx_bytes_old != it->tx_bytes)) {
            tx_rate = it->tx_bytes - tx_bytes_old;
            tx_bytes_old = it->tx_bytes;
        }

        if (it->rx_bytes != 0 && (rx_bytes_old != it->rx_bytes)) {
            rx_rate = it->rx_bytes - rx_bytes_old;
            rx_bytes_old = it->rx_bytes;
        }

        tx_rates.push_back(TO_KBIT(tx_rate));
        rx_rates.push_back(TO_KBIT(rx_rate));
    }

    return std::make_pair(tx_rates, rx_rates);
}

std::string json_resource_usage_history(FCGX_Request *request)
{
    std::ostringstream ss_json;
    ss_json << "{";

    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageResourceHistory msg;
    std::string interface_name = "eth0"; // TODO: The user will choose the interface name with WEB UI
    msg.set_interface_name(interface_name);
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

        std::pair<tx_rates_t, rx_rates_t> rates = calculate_rates(msg.get_network_history());

        ss_json << ",\"json_network_history\": {";
        ss_json << "\"tx_bytes\":[";

        counter = 0;
        for (auto const &tx_rate : rates.first) {
            counter++;

            ss_json << tx_rate;

            if (counter < rates.first.size()) {
                ss_json << ",";
            }
        }

        ss_json << "]";
        ss_json << ",\"rx_bytes\":[";

        counter = 0;
        for (auto const &rx_rate : rates.second) {
            counter++;

            ss_json << rx_rate;

            if (counter < rates.second.size()) {
                ss_json << ",";
            }
        }

        ss_json << "]}";
    }

    ss_json << "}";

    return ss_json.str();
}
