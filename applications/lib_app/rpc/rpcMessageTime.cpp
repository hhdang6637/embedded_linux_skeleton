/*
 * rpcMessageTime.cpp
 *
 *  Created on: Jan 19, 2019
 *      Author: nmhien
 */

#include "rpcUnixClient.h"

#include "rpcMessageTime.h"

namespace app
{

    rpcMessageTime::rpcMessageTime() :
            rpcMessage(rpcMessageType::handle_time_cfg, rpcMessageAddr::system_manager_addr_t),
            msgResult(app::rpcMessageTimeResultType::UNKNOWN),
            msgAction(app::rpcMessageTimeActionType::GET_SYSTEM_TIME)
    {
        // TODO Auto-generated constructor stub

    }

    rpcMessageTime::~rpcMessageTime()
    {
        // TODO Auto-generated destructor stub
    }

    bool rpcMessageTime::serialize(int fd)
    {
        // TODO

        return true;
    }

    bool rpcMessageTime::deserialize(int fd)
    {
        // TODO

        return true;
    }

    app::rpcMessageTimeActionType rpcMessageTime::getMsgAction() const
    {
        return this->msgAction;
    }

    void rpcMessageTime::setMsgAction(const rpcMessageTimeActionType action)
    {
        this->msgAction = action;
    }

    app::rpcMessageTimeResultType rpcMessageTime::getMsgResult() const
    {
        return this->msgResult;
    }

    void rpcMessageTime::setMsgResult(const app::rpcMessageTimeResultType result)
    {
        this->msgResult = result;
    }

    struct tm rpcMessageTime::getSystemTime() const
    {
        return this->systemTime;
    }

    void rpcMessageTime::setSystemTime(const struct tm &time)
    {
        this->systemTime = time;
    }

    app::rpcMessageTimeResultType rpcMessageTime::rpcGetSystemTime(app::rpcUnixClient &rpcClient, struct tm& time)
    {
        app::rpcMessageTime msg;

        msg.setMsgAction(app::rpcMessageTimeActionType::GET_SYSTEM_TIME);

        if (rpcClient.doRpc(&msg) == false) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return app::rpcMessageTimeResultType::UNKNOWN;
        }

        time = msg.getSystemTime();

        return msg.getMsgResult();
    }

    app::rpcMessageTimeResultType rpcMessageTime::rpcSetSystemTime(app::rpcUnixClient &rpcClient, const struct tm& time)
    {
        app::rpcMessageTime msg;

        msg.setMsgAction(app::rpcMessageTimeActionType::SET_SYSTEM_TIME);

        msg.setSystemTime(time);

        if (rpcClient.doRpc(&msg) == false) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return app::rpcMessageTimeResultType::UNKNOWN;
        }

        return msg.getMsgResult();
    }

    std::string rpcMessageTime::timeMsgResult2Str(const app::rpcMessageTimeResultType &result)
    {
        std::string outStr;

        switch (result)
        {
            case app::rpcMessageTimeResultType::FAILED:
                outStr = "Failed";
                break;

            case app::rpcMessageTimeResultType::SUCCESS:
                outStr = "Success";
                break;

            case app::rpcMessageTimeResultType::UNKNOWN:
                outStr = "Unknown";
                break;
        }

        return outStr;
    }

} /* namespace app */
