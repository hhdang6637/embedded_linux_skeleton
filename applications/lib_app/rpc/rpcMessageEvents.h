/*
 * rpcMessageEvents.h
 *
 *  Created on: Aug 30, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEEVENTS_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEEVENTS_H_

#include "rpcMessage.h"

namespace app
{
    class rpcMessageEvents: public rpcMessage
    {
    public:
        rpcMessageEvents();
        virtual ~rpcMessageEvents();

        virtual bool serialize(int fd);
        virtual bool deserialize(int fd);

        void     setEvents(uint16_t events);
        uint16_t getEvents();
    private:
        uint16_t events;
    };

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEEVENTS_H_ */
