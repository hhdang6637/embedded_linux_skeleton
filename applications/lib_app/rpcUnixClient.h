/*
 * rpcUnixClient.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCUNIXCLIENT_H_
#define APPLICATIONS_LIB_APP_RPCUNIXCLIENT_H_

#include "rpcMessage.h"

namespace app
{

class rpcUnixClient
{
private:
    rpcUnixClient();
    int connect(rpcMessageAddr &addr);

    static rpcUnixClient* s_instance;
public:
    virtual ~rpcUnixClient();
    bool doRpc(rpcMessage *msg);

    static rpcUnixClient* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCUNIXCLIENT_H_ */
