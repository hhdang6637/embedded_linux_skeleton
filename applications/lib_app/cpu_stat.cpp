/*
 * cpu_stat.cpp
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#include <stdio.h>

#include "cpu_stat.h"


bool get_cpu_stat(cpu_stat_t *stat)
{
    static const char fmt[] = "cpu %llu %llu %llu %llu %llu %llu %llu %llu";

    FILE * f;
    f = fopen("/proc/stat", "r");
    if (f != NULL) {

        int ret = fscanf(f, fmt, &stat->usr, &stat->nic, &stat->sys, &stat->idle,
                &stat->iowait, &stat->irq, &stat->softirq, &stat->steal);

        if (ret >= 4) {
            stat->total = stat->usr + stat->nic + stat->sys + stat->idle
                    + stat->iowait + stat->irq + stat->softirq
                    + stat->steal;
            /* procps 2.x does not count iowait as busy time */
            stat->busy = stat->total - stat->idle - stat->iowait;
        }

        fclose(f);
        return true;
    }

    return false;
}
