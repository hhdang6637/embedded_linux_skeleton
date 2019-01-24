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

                buff_len += sizeof(uint16_t) + strlen(this->getNtpCfg().ntp_server);
                buff_len += sizeof(uint16_t);
                buff_len += sizeof(uint16_t); // this->msgResult;

                std::unique_ptr<char> buff_ptr(new char[buff_len]);
                std::string ntp_server(this->getNtpCfg().ntp_server);
                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, ntp_server);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, this->getNtpCfg().state);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, this->getMsgResult());

                syslog(LOG_INFO, "rpcMessage::serialize: ntp_server_size: %d\n", strlen(this->getNtpCfg().ntp_server));
                syslog(LOG_INFO, "rpcMessage::serialize: enable_ntp: %d\n", this->getNtpCfg().state);
                syslog(LOG_INFO, "rpcMessage::serialize: ntp_server: %s\n", this->getNtpCfg().ntp_server);

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

                buff_len += sizeof(uint32_t); // for day
                buff_len += sizeof(uint32_t); // for month
                buff_len += sizeof(uint32_t); // for year
                buff_len += sizeof(uint32_t); // for hh
                buff_len += sizeof(uint32_t); // for mm
                buff_len += sizeof(uint16_t); // this->msgResult;

                std::unique_ptr<char> buff_ptr(new char[buff_len]);
                offset += rpcMessage::bufferAppendU32(buff_ptr.get() + offset, (uint32_t) getSystemTime().tm_mday);
                offset += rpcMessage::bufferAppendU32(buff_ptr.get() + offset, (uint32_t) getSystemTime().tm_mon);
                offset += rpcMessage::bufferAppendU32(buff_ptr.get() + offset, (uint32_t) getSystemTime().tm_year);
                offset += rpcMessage::bufferAppendU32(buff_ptr.get() + offset, (uint32_t) getSystemTime().tm_hour);
                offset += rpcMessage::bufferAppendU32(buff_ptr.get() + offset, (uint32_t) getSystemTime().tm_min);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, this->getMsgResult());

                syslog(LOG_INFO, "Serialize: time: H=%d M=%d\n", getSystemTime().tm_hour, getSystemTime().tm_min);
                syslog(LOG_INFO, "Serialize: date: d=%d m=%d y=%d\n", getSystemTime().tm_mday, getSystemTime().tm_mon, getSystemTime().tm_year);

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
                uint16_t ntp_server_size;
                app::ntpConfig_t ntpCfgTmp;

                if (rpcMessage::recvInterruptRetry(fd, &ntp_server_size, sizeof(uint16_t)) != true) {
                    return false;
                }
                syslog(LOG_INFO, "rpcMessage::recvInterruptRetry: ntp_server_size: %d\n", ntp_server_size);

                if(ntp_server_size > 0)
                {
                    memset(ntpCfgTmp.ntp_server, 0, sizeof(ntpCfgTmp.ntp_server));
                    char ntp_server[ntp_server_size];
                    if (rpcMessage::recvInterruptRetry(fd, ntp_server, ntp_server_size) != true) {
                        return false;
                    }
                    strncpy(ntpCfgTmp.ntp_server, ntp_server, ntp_server_size);
                }

                if (rpcMessage::recvInterruptRetry(fd, &ntpCfgTmp.state, sizeof(uint16_t)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult, sizeof(uint16_t)) != true) {
                    return false;
                }

                this->setNtpCfg(ntpCfgTmp);
                syslog(LOG_INFO, "rpcMessage::recvInterruptRetry: enable_ntp: %d\n", this->getNtpCfg().state);
                syslog(LOG_INFO, "rpcMessage::recvInterruptRetry: ntp_server: %s\n", this->getNtpCfg().ntp_server);
                break;
            }
            case app::rpcMessageTimeActionType::GET_SYSTEM_TIME:
            case app::rpcMessageTimeActionType::SET_SYSTEM_TIME:
            {
                tm date_time;
                if (rpcMessage::recvInterruptRetry(fd, &date_time.tm_mday, sizeof(uint32_t)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &date_time.tm_mon, sizeof(uint32_t)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &date_time.tm_year, sizeof(uint32_t)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &date_time.tm_hour, sizeof(uint32_t)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &date_time.tm_min, sizeof(uint32_t)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult, sizeof(uint16_t)) != true) {
                    return false;
                }

                this->setSystemTime(date_time);
                syslog(LOG_INFO, "Deserialize: time: H=%d M=%d\n", getSystemTime().tm_hour, getSystemTime().tm_min);
                syslog(LOG_INFO, "Deserialize: date: d=%d m=%d y=%d\n", getSystemTime().tm_mday, getSystemTime().tm_mon, getSystemTime().tm_year);
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
