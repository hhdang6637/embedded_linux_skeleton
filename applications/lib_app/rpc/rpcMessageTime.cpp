/*
 * rpcMessageTime.cpp
 *
 *  Created on: Jan 19, 2019
 *      Author: nmhien
 */

#include "rpcUnixClient.h"
#include <memory>
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
        uint16_t tmpValue;
        tmpValue = (uint16_t) this->msgAction;
        if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        switch (this->msgAction)
        {
            case app::rpcMessageTimeActionType::GET_NTP_CONFIG:
            case app::rpcMessageTimeActionType::SET_NTP_CONFIG:
            {
                int buff_len = 0;
                int offset = 0;

                buff_len += sizeof(this->msgResult);
                buff_len += sizeof(ntpConfig_t);

                std::unique_ptr<char> buff_ptr(new char[buff_len]);

                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->msgResult);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->ntpCfg);

                if (buff_len != offset) {
                    syslog(LOG_ERR, "%s-%u something wrong happened", __FUNCTION__, __LINE__);
                    return false;
                }

                if (rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
                    return false;
                }

                break;
            }
            case app::rpcMessageTimeActionType::GET_SYSTEM_TIME:
            case app::rpcMessageTimeActionType::SET_SYSTEM_TIME:
            {
                int buff_len = 0;
                int offset = 0;

                buff_len += sizeof(this->msgResult);
                buff_len += sizeof(struct tm);

                std::unique_ptr<char> buff_ptr(new char[buff_len]);

                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->msgResult);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->systemTime);

                if (buff_len != offset) {
                    syslog(LOG_ERR, "%s-%u something wrong happened", __FUNCTION__, __LINE__);
                    return false;
                }

                if (rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
                    return false;
                }

                break;
            }
            default:
                break;
        }

        return true;
    }

    bool rpcMessageTime::deserialize(int fd)
    {
        uint16_t tmpValue;
        if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        this->msgAction = app::rpcMessageTimeActionType(tmpValue);

        switch (this->msgAction)
        {
            case app::rpcMessageTimeActionType::GET_NTP_CONFIG:
            case app::rpcMessageTimeActionType::SET_NTP_CONFIG:
            {
                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult, sizeof(this->msgResult)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->ntpCfg, sizeof(this->ntpCfg)) != true) {
                    return false;
                }

                break;
            }
            case app::rpcMessageTimeActionType::GET_SYSTEM_TIME:
            case app::rpcMessageTimeActionType::SET_SYSTEM_TIME:
            {
                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult, sizeof(this->msgResult)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->systemTime, sizeof(this->systemTime)) != true) {
                    return false;
                }

                break;
            }
            default:
                break;
        }

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

    struct tm const &rpcMessageTime::getSystemTime() const
    {
        return this->systemTime;
    }

    void rpcMessageTime::setSystemTime(const struct tm &time)
    {
        this->systemTime = time;
    }

    ntpConfig_t const &rpcMessageTime::getNtpCfg() const
    {
        return this->ntpCfg;
    }

    void rpcMessageTime::setNtpCfg(const ntpConfig_t &cfg)
    {
        this->ntpCfg = cfg;
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

    app::rpcMessageTimeResultType rpcMessageTime::rpcGetNtpCfg(app::rpcUnixClient &rpcClient, ntpConfig_t& cfg)
    {
        app::rpcMessageTime msg;

        msg.setMsgAction(app::rpcMessageTimeActionType::GET_NTP_CONFIG);

        if (rpcClient.doRpc(&msg) == false) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return app::rpcMessageTimeResultType::UNKNOWN;
        }

        cfg = msg.getNtpCfg();

        return msg.getMsgResult();
    }

    app::rpcMessageTimeResultType rpcMessageTime::rpcSetNtpCfg(app::rpcUnixClient &rpcClient, const ntpConfig_t& cfg)
    {
        app::rpcMessageTime msg;

        msg.setMsgAction(app::rpcMessageTimeActionType::SET_NTP_CONFIG);

        msg.setNtpCfg(cfg);

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
