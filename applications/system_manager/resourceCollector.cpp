/*
 * resourceCollector.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include <stdio.h>

#include "resourceCollector.h"

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
    static const char fmt[] = "cpu %llu %llu %llu %llu %llu %llu %llu %llu";

    cpu_stat_t stat = {0};

    FILE * f;
    f = fopen("/proc/stat", "r");
    if (f != NULL) {

        int ret = fscanf(f, fmt, &stat.usr, &stat.nic, &stat.sys, &stat.idle,
                &stat.iowait, &stat.irq, &stat.softirq, &stat.steal);

        if (ret >= 4) {
            stat.total = stat.usr + stat.nic + stat.sys + stat.idle
                    + stat.iowait + stat.irq + stat.softirq
                    + stat.steal;
            /* procps 2.x does not count iowait as busy time */
            stat.busy = stat.total - stat.idle - stat.iowait;

            if (this->cpu_history.size() >= resourceCollector::cpu_history_max_sample) {
                this->cpu_history.pop_front();
            }

            this->cpu_history.push_back(stat);
        }

        fclose(f);
    }
}

} /* namespace app */
