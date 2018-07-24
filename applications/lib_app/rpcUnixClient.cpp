/*
 * rpcUnixClient.cpp
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "rpcUnixClient.h"

namespace app
{

rpcUnixClient::rpcUnixClient()
{
    // TODO Auto-generated constructor stub
}

rpcUnixClient::~rpcUnixClient()
{
    // TODO Auto-generated destructor stub
}

int rpcUnixClient::connect(rpcMessageAddr addr)
{
    int socket_fd = -1;

    if ( (socket_fd = ::socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    if (::connect(socket_fd, (struct sockaddr*)&addr.addr, sizeof(addr.addr)) == -1) {
        goto error_exit;
    }

    return socket_fd;

error_exit:

    if (socket_fd != -1) {
        close(socket_fd);
    }

    return -1;
}

bool rpcUnixClient::doRpc(rpcMessage *msg)
{
    bool rc = false;
    int sock_fd = this->connect(rpcMessageAddr::getRpcMessageAddrbyType(msg->msgAddrType));

    if (sock_fd != -1) {
        if (msg->send(sock_fd) == true) {
            if (msg->receive(sock_fd) == true) {
                rc = true;
            }
        }
        close (sock_fd);
    }

    return rc;
}

rpcUnixClient *rpcUnixClient::s_instance = 0;

rpcUnixClient* rpcUnixClient::getInstance()
{
    if (s_instance == 0) {
        s_instance = new rpcUnixClient();
    }

    return s_instance;
}

} /* namespace app */
