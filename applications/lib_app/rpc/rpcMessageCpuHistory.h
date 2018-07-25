/*
 * rpcMessageCpuHistory.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_

#include <list>

#include "cpu_stat.h"
#include "rpcMessage.h"

namespace app
{

class rpcMessageCpuHistory: public rpcMessage
{
	std::list<cpu_stat_t> cpu_history;
public:
	virtual bool serialize(int fd);
	virtual bool deserialize(int);

    rpcMessageCpuHistory();
    virtual ~rpcMessageCpuHistory();
    std::list<cpu_stat_t> get_cpu_history(){return this->cpu_history;};
	void set_cpu_history(std::list<cpu_stat_t> &cpu_history) { this->cpu_history = cpu_history; };
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGECPUHISTORY_H_ */
