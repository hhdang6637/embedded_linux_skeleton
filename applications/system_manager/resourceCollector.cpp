/*
 * resourceCollector.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */

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
	cpu_stat_t stat = { 0 };

	if (::get_cpu_stat(&stat) == true) {

		if (this->cpu_history.size() >= resourceCollector::cpu_history_max_sample) {
			this->cpu_history.pop_front();
		}

		this->cpu_history.push_back(stat);
	}
}

} /* namespace app */
