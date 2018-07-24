/*
 * rpcUnixServer.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCUNIXSERVER_H_
#define APPLICATIONS_LIB_APP_RPCUNIXSERVER_H_

#include <map>
#include <functional>

#include "rpcMessage.h"

namespace app
{

typedef std::function<bool(int)> messageHandler;

class rpcUnixServer
{
private:
    rpcMessageAddr listenAddr;
    rpcUnixServer();

    bool listened;
    int sock_fd;
    std::map<app::rpcMessage::rpcMessageType, messageHandler> messageHandlers;

    static rpcUnixServer* s_instance;
public:
    virtual ~rpcUnixServer();

    bool openServer(rpcMessageAddr addr);
    bool stopServer();
    int get_socket() {return this->sock_fd;}
    bool registerMessageHandler(app::rpcMessage::rpcMessageType, messageHandler);
    bool doReply();

    static rpcUnixServer* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCUNIXSERVER_H_ */
