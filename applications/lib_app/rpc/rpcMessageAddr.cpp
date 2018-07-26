/*
 * rpcMessageAddr.cpp
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */
#include <sys/socket.h>
#include <string.h>

#include "rpcMessageAddr.h"

namespace app
{

rpcMessageAddr::rpcMessageAddr(const char*path)
{
    memset(&this->addr, 0, sizeof(this->addr));
    this->addr.sun_family = AF_UNIX;
    strncpy(this->addr.sun_path, path, sizeof(this->addr.sun_path) - 1);
}

rpcMessageAddr::~rpcMessageAddr()
{
    // TODO Auto-generated destructor stub
}

rpcMessageAddr rpcMessageAddr::getRpcMessageAddrbyType(rpcMessageAddrType addrType)
{
    switch (addrType) {
        case system_manager_addr_t:
            return rpcMessageAddr("/tmp/system_manager.socket");
            break;
        default:
            return rpcMessageAddr("/tmp/system_manager.socket");
            break;
    }
}

} /* namespace app */