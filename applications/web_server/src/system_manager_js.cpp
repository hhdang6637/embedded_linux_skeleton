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

std::string json_cpu_usage_history(const char*url)
{

    static std::list<int> cpu_usage_history;

    if (cpu_usage_history.size() == 0) {

        cpu_usage_history.push_back(50);

        for (int i = 0; i < 60; i++) {
            int y = cpu_usage_history.back() + (rand() % 10) - 5;
            if (y < 0) {
                y = 0;
            } else if (y > 100) {
                y = 100;
            }
            cpu_usage_history.push_back(y);
        }
    }

    int latest = cpu_usage_history.back() + (rand() % 10) - 5;
    if (latest < 0) {
        latest = 0;
    } else if (latest > 100) {
        latest = 100;
    }

    cpu_usage_history.pop_front();

    std::ostringstream ss_json;

    ss_json << "{\"json_cpu_usage_history\":[";

    for (auto const& i : cpu_usage_history) {
        ss_json << i;
        ss_json << ",";
    }

    cpu_usage_history.push_back(latest);
    ss_json << cpu_usage_history.back();

    ss_json << "]}";

    return ss_json.str();
}
