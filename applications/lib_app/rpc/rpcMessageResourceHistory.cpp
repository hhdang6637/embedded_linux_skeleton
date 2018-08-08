/*
 * rpcMessageResourceHistory.cpp
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#include <arpa/inet.h>
#include <string.h>
#include <syslog.h>
#include <memory>

#include "rpcMessageResourceHistory.h"

namespace app
{

rpcMessageResourceHistory::rpcMessageResourceHistory() : rpcMessage(rpcMessageType::get_resource_history)
{
}

rpcMessageResourceHistory::~rpcMessageResourceHistory()
{
    // TODO Auto-generated destructor stub
}

bool rpcMessageResourceHistory::serialize(int fd)
{
    // just write the state
    int buff_len = 0;
    buff_len += sizeof(uint16_t) + this->cpu_history.size() * sizeof(cpu_stat_t);
    buff_len += sizeof(uint16_t) + this->ram_history.size() * sizeof(struct sysinfo);
    buff_len += sizeof(uint16_t) + this->interface_name.length();
    buff_len += sizeof(uint16_t) + this->network_history.size() * sizeof(struct net_device_stats);

    std::unique_ptr<char> buff_ptr(new char[buff_len]);

    int offset = 0;
    offset += rpcMessage::bufferAppendList(buff_ptr.get() + offset, this->cpu_history);
    offset += rpcMessage::bufferAppendList(buff_ptr.get() + offset, this->ram_history);
    offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->interface_name);
    offset += rpcMessage::bufferAppendList(buff_ptr.get() + offset, this->network_history);

    if (buff_len != offset) {
        syslog(LOG_ERR, "%s:%u:%s something wrong happened", __FILE__, __LINE__,__FUNCTION__);
        return false;
    }

    if(rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
        return false;
    }

    return true;
}

bool rpcMessageResourceHistory::deserialize(int fd)
{
    uint16_t cpu_history_size, ram_history_size, network_history_size, interface_name_size;

    if (rpcMessage::recvInterruptRetry(fd, &cpu_history_size, sizeof(cpu_history_size)) != true) {
        return false;
    }

    if (cpu_history_size > 0) {
        std::unique_ptr<char> buff_ptr(new char[cpu_history_size * sizeof(cpu_stat_t)]);

        if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), cpu_history_size * sizeof(cpu_stat_t)) != true) {
            return false;
        }

        rpcMessage::ListFromBuff((cpu_stat_t*) buff_ptr.get(), this->cpu_history, cpu_history_size);
    }

    if (rpcMessage::recvInterruptRetry(fd, &ram_history_size, sizeof(ram_history_size)) != true) {
        return false;
    }

    if (ram_history_size > 0) {
        std::unique_ptr<char> buff_ptr(new char[ram_history_size * sizeof(struct sysinfo)]);

        if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), ram_history_size * sizeof(struct sysinfo)) != true) {
            return false;
        }

        rpcMessage::ListFromBuff((struct sysinfo*) buff_ptr.get(), this->ram_history, ram_history_size);
    }

    if (rpcMessage::recvInterruptRetry(fd, &interface_name_size, sizeof(interface_name_size)) != true) {
        return false;
    }

    if (interface_name_size > 0) {
        std::unique_ptr<char> buff_ptr(new char[interface_name_size + 1]());

        if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), interface_name_size) != true) {
            return false;
        }

        this->interface_name = buff_ptr.get();
    }

    if (rpcMessage::recvInterruptRetry(fd, &network_history_size, sizeof(network_history_size)) != true) {
        return false;
    }

    if (network_history_size > 0) {
        std::unique_ptr<char> buff_ptr(new char[network_history_size * sizeof(struct net_device_stats)]);

        if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), network_history_size * sizeof(struct net_device_stats)) != true) {
            return false;
        }

        rpcMessage::ListFromBuff((struct net_device_stats*) buff_ptr.get(), this->network_history, network_history_size);
    }

    return true;
}

} /* namespace app */
