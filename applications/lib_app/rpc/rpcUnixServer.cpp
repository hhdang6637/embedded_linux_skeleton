/*
 * rpcUnixServer.cpp
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "rpcUnixServer.h"

namespace app
{

bool rpcUnixServer::openServer(rpcMessageAddr addr)
{
    if(this->listened == true || this->sock_fd != -1) {
        return false;
    }

    this->listenAddr = addr;

    if ((this->sock_fd = ::socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        goto error_exit;
    }

    if (::bind(this->sock_fd, (struct sockaddr*) &this->listenAddr.addr, sizeof(this->listenAddr.addr.sun_path) - 1) == -1) {
        goto error_exit;
    }

    if (::listen(this->sock_fd, 20) == -1) {
        goto error_exit;
    }

    this->listened = true;

    return true;

error_exit:

    if (this->sock_fd != -1) {
        close(this->sock_fd);
    }

    return false;
}

bool rpcUnixServer::stopServer()
{
    listened = false;

    if (sock_fd != -1) {
        ::unlink(this->listenAddr.addr.sun_path);
        close(sock_fd);
    }

    return true;
}

bool rpcUnixServer::registerMessageHandler(app::rpcMessage::rpcMessageType msgType, messageHandler cb)
{
    return this->messageHandlers.insert(std::pair<app::rpcMessage::rpcMessageType, messageHandler>(msgType, cb)).second;
}

bool rpcUnixServer::doReply()
{
    int rc = false;
    int client_socket;

    client_socket = ::accept(this->sock_fd, NULL, NULL);

    if (client_socket == -1) {
        syslog(LOG_ERR, "accept failed");
        return false;
    }

    uint16_t msgTypeNumber = 0;

    if (rpcMessage::recvInterruptRetry(client_socket, &msgTypeNumber, sizeof(uint16_t)) != true) {
        return false;
    } else {

        auto it = this->messageHandlers.find(app::rpcMessage::rpcMessageType(msgTypeNumber));
        if (it != this->messageHandlers.end()) {
            rc = it->second(client_socket);
        } else {
            char buff[256];
            snprintf(buff, sizeof(buff), "cannot find messageHandler for messageType %u", msgTypeNumber);
            syslog(LOG_ERR, buff);
        }
    }

    ::close(client_socket);

    return rc;
}

rpcUnixServer::rpcUnixServer() : listenAddr(""), listened(false), sock_fd(-1)
{
    memset(&this->listenAddr, 0, sizeof(this->listenAddr));
}

rpcUnixServer::~rpcUnixServer()
{

}

rpcUnixServer *rpcUnixServer::s_instance = 0;

rpcUnixServer* rpcUnixServer::getInstance()
{
    if (s_instance == 0) {
        s_instance = new rpcUnixServer();
    }

    return s_instance;
}

} /* namespace app */
