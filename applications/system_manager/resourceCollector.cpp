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

std::list<jiffy_counts_t> resourceCollector::get_cpu_history()
{
    return this->cpu_history;
}

void resourceCollector::cpu_do_collect()
{
    static const char fmt[] = "cpu %llu %llu %llu %llu %llu %llu %llu %llu";

    jiffy_counts_t p_jif = {0};

    FILE * f;
    f = fopen("/proc/stat", "r");
    if (f != NULL) {

        int ret = fscanf(f, fmt, &p_jif.usr, &p_jif.nic, &p_jif.sys, &p_jif.idle,
                &p_jif.iowait, &p_jif.irq, &p_jif.softirq, &p_jif.steal);

        if (ret >= 4) {
            p_jif.total = p_jif.usr + p_jif.nic + p_jif.sys + p_jif.idle
                    + p_jif.iowait + p_jif.irq + p_jif.softirq
                    + p_jif.steal;
            /* procps 2.x does not count iowait as busy time */
            p_jif.busy = p_jif.total - p_jif.idle - p_jif.iowait;
        }

        this->cpu_history.push_back(p_jif);
        if (this->cpu_history.size() > 60) {
            this->cpu_history.pop_front();
        }

        fclose(f);
    }
}

} /* namespace app */
