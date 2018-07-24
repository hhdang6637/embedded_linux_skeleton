/*
 * rpcMessage.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGE_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGE_H_

#include "rpcMessageAddr.h"

namespace app
{
class rpcUnixClient;

class rpcMessage
{
    enum rpcMessageState {request, reply};
private:
    rpcMessageState state;
    rpcMessageAddr addr;
public:
    rpcMessage(rpcMessageAddr addr);
    virtual ~rpcMessage();

    bool send(int fd);
    bool receive(int fd);

    friend class rpcUnixClient;
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGE_H_ */
