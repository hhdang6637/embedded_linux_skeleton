/*
 * rpcMessageEvents.cpp
 *
 *  Created on: Aug 30, 2018
 *      Author: nmhien
 */

#include "rpcMessageEvents.h"

namespace app
{

    rpcMessageEvents::rpcMessageEvents():
                rpcMessage(rpcMessageType::get_event_notification, rpcMessageAddr::event_manager_addr_t),
                events(0)
    {
        // TODO Auto-generated constructor stub

    }

    rpcMessageEvents::~rpcMessageEvents()
    {
        // TODO Auto-generated destructor stub
    }

    bool rpcMessageEvents::serialize(int fd)
    {
        if (rpcMessage::sendInterruptRetry(fd, &this->events, sizeof(this->events)) != true) {
            return false;
        }

        return true;
    }

    bool rpcMessageEvents::deserialize(int fd)
    {
        if (rpcMessage::recvInterruptRetry(fd, &this->events, sizeof(this->events)) != true) {
            return false;
        }

        return true;
    }

    void rpcMessageEvents::setEvents(uint16_t events)
    {
        this->events = events;
    }

    uint16_t rpcMessageEvents::getEvents()
    {
        return this->events;
    }

} /* namespace app */
