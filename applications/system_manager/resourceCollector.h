/*
 * resourceCollector.h
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_
#define APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_

#include <list>

#include "cpu_stat.h"

namespace app {

class resourceCollector {
private:
    resourceCollector();
    static resourceCollector* s_instance;

    std::list<cpu_stat_t> cpu_history;
public:
    virtual ~resourceCollector();

    std::list<cpu_stat_t> get_cpu_history();
    void cpu_do_collect();

    static resourceCollector* getInstance();
    static const int cpu_history_max_sample = 60;
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_RESOURCECOLLECTOR_H_ */
