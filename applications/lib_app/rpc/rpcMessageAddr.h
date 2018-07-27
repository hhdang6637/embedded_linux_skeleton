/*
 * rpcMessageAddr.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGEADDR_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGEADDR_H_

#include <sys/un.h>

namespace app
{
class rpcUnixClient;
class rpcUnixServer;

class rpcMessageAddr
{
private:
    rpcMessageAddr(const char*path);

    struct sockaddr_un addr;
public:

    enum rpcMessageAddrType {
        system_manager_addr_t,
        network_manager_addr_t
    };

    virtual ~rpcMessageAddr();

    static rpcMessageAddr getRpcMessageAddrbyType(rpcMessageAddrType addrType);

    friend class rpcUnixClient;
    friend class rpcUnixServer;
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGEADDR_H_ */
