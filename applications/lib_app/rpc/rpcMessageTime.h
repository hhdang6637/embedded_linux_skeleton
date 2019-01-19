/*
 * rpcMessageTime.h
 *
 *  Created on: Jan 19, 2019
 *      Author: nmhien
 */

#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGETIME_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGETIME_H_

#include "rpcMessage.h"

namespace app
{

    enum rpcMessageTimeResultType: int16_t
    {
        FAILED = 0,
        SUCCESS,
        UNKNOWN
    };

    enum rpcMessageTimeActionType: int16_t {
        GET_SYSTEM_TIME,
        SET_SYSTEM_TIME,
    };

    class rpcMessageTime: public rpcMessage
    {
    public:
        rpcMessageTime();
        virtual ~rpcMessageTime();

        virtual bool serialize(int fd);
        virtual bool deserialize(int);

        app::rpcMessageTimeActionType        getMsgAction(void) const;
        void                                 setMsgAction(const rpcMessageTimeActionType action);

        app::rpcMessageTimeResultType        getMsgResult(void) const;
        void                                 setMsgResult(const rpcMessageTimeResultType result);

        struct tm                            getSystemTime(void) const;
        void                                 setSystemTime(const struct tm &time);

        static app::rpcMessageTimeResultType rpcSetSystemTime(app::rpcUnixClient &rpcClient, const struct tm& time);
        static app::rpcMessageTimeResultType rpcGetSystemTime(app::rpcUnixClient &rpcClient, struct tm& time);

        static std::string                   timeMsgResult2Str(const rpcMessageTimeResultType &result);

    private:
        app::rpcMessageTimeResultType msgResult;
        app::rpcMessageTimeActionType msgAction;
        struct tm                     systemTime;
    };

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGETIME_H_ */
