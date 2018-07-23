/*
 * resourceCollector.h
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_
#define APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_

#include <list>

namespace app {

typedef struct jiffy_counts_t {
    /* Linux 2.4.x has only first four */
    unsigned long long usr, nic, sys, idle;
    unsigned long long iowait, irq, softirq, steal;
    unsigned long long total;
    unsigned long long busy;
} jiffy_counts_t;

class resourceCollector {
private:
    resourceCollector();
    static resourceCollector* s_instance;

    std::list<jiffy_counts_t> cpu_history;
public:
    virtual ~resourceCollector();

    std::list<jiffy_counts_t> get_cpu_history();
    void cpu_do_collect();

    static resourceCollector* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_ */
