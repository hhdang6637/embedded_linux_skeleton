/*
 * cpu_stat.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_CPU_STAT_H_
#define APPLICATIONS_LIB_APP_CPU_STAT_H_

typedef struct cpu_stat_t {
    unsigned long long usr, nic, sys, idle;
    unsigned long long iowait, irq, softirq, steal;
    unsigned long long total;
    unsigned long long busy;
} cpu_stat_t;

bool get_cpu_stat(cpu_stat_t *);

#endif /* APPLICATIONS_LIB_APP_CPU_STAT_H_ */
