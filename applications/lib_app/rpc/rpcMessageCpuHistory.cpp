/*
 * rpcMessageCpuHistory.cpp
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>
#include <memory>

#include "rpcMessageCpuHistory.h"

namespace app
{

rpcMessageCpuHistory::rpcMessageCpuHistory() : rpcMessage(rpcMessageType::get_cpu_history)
{
}

rpcMessageCpuHistory::~rpcMessageCpuHistory()
{
    // TODO Auto-generated destructor stub
}

bool rpcMessageCpuHistory::serialize(int fd)
{
    // just write the state
    int buff_len = sizeof(uint16_t) + this->cpu_history.size() * sizeof(cpu_stat_t);
    std::unique_ptr<char> buff_ptr(new char[buff_len]);

    int offset = 0;
    uint16_t tmp;
    tmp = this->cpu_history.size();
    offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, tmp);
    offset += rpcMessage::bufferAppendList(buff_ptr.get() + offset, this->cpu_history);

    if (buff_len != offset) {
        char buff[256];
        snprintf(buff, sizeof(buff), "%s-%u something wrong happened", __FUNCTION__, __LINE__);
        syslog(LOG_ERR, buff);
    }

    if (::send(fd, buff_ptr.get(), offset, 0) == offset) {
        return true;
    } else {
        char buff[256];
        snprintf(buff, sizeof(buff), "%s-%u: cannot send buff successful", __FUNCTION__, __LINE__);
        syslog(LOG_ERR, buff);
    }

    return false;
}

bool rpcMessageCpuHistory::deserialize(int fd)
{
    uint16_t cpu_history_size;
    if (::recv(fd, &cpu_history_size, sizeof(cpu_history_size), 0) != sizeof(cpu_history_size)) {
        return false;
    }

    if (cpu_history_size > 0) {
        std::unique_ptr<char> buff_ptr(new char[cpu_history_size * sizeof(cpu_stat_t)]);
        if (::recv(fd, buff_ptr.get(), cpu_history_size * sizeof(cpu_stat_t), 0)
                != (ssize_t) (cpu_history_size * sizeof(cpu_stat_t))) {
            return false;
        }
        rpcMessage::ListFromBuff((cpu_stat_t*) buff_ptr.get(), this->cpu_history, cpu_history_size);
    }

    return true;
}

} /* namespace app */
