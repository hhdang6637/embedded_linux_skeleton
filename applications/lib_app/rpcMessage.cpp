/*
 * rpcMessage.cpp
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#include "rpcMessage.h"

namespace app
{

rpcMessage::rpcMessage(rpcMessageAddr addr)
{
    this->state = rpcMessage::rpcMessageState::request;
    this->addr = addr;
}

rpcMessage::~rpcMessage()
{
    // TODO Auto-generated destructor stub
}

bool rpcMessage::send(int fd)
{
    // TODO
    return true;
}

bool rpcMessage::receive(int fd)
{
    // TODO
    return true;
}

} /* namespace app */
