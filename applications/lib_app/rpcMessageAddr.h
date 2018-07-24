/*
 * rpcMessageAddr.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGEADDR_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGEADDR_H_

namespace app
{

class rpcMessageAddr
{
protected:
    struct sockaddr_un addr;
public:
    rpcMessageAddr();
    virtual ~rpcMessageAddr();
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGEADDR_H_ */
