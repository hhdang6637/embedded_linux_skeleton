/*
 * rpcMessageUsers.cpp
 *
 *  Created on: Aug 11, 2018
 *      Author: hhdang
 */

#include <memory>

#include "rpcMessageWifiSetting.h"

namespace app
{

    rpcMessageWifiSetting::rpcMessageWifiSetting():
                                                    rpcMessage(rpcMessageType::handle_wifi_setting, rpcMessageAddr::network_manager_addr_t)
    {
        //TO-DO
        memset(this->msgData.presharedKey, 0, sizeof(this->msgData.presharedKey));
        memset(this->msgData.ssid, 0, sizeof(this->msgData.ssid));
    }

    rpcMessageWifiSetting::~rpcMessageWifiSetting()
    {
        //TO-DO
    }

    bool rpcMessageWifiSetting::serialize(int fd)
    {
        uint16_t tmpValue;
        tmpValue = (uint16_t)this->msgAction;
        if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        switch (this->msgAction) {
            case app::rpcMessageWifiSettingActionType::GET_WIFI_SETTING:
            case app::rpcMessageWifiSettingActionType::EDIT_WIFI_SETTING:
            {
                int buff_len = 0;
                int offset   = 0;

                buff_len += sizeof(uint16_t) + strlen(this->msgData.presharedKey);
                buff_len += sizeof(uint16_t) + strlen(this->msgData.ssid);
                buff_len += sizeof(uint16_t); // this->msgData.accessPoint;
                buff_len += sizeof(uint16_t); // this->msgData.securityType;
                buff_len += sizeof(uint16_t); // this->msgResult;

                std::unique_ptr<char> buff_ptr(new char[buff_len]);
                std::string presharedKey(this->msgData.presharedKey);
                std::string ssid(this->msgData.ssid);
                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, presharedKey);
                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, ssid);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, this->msgData.accessPoint );
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, this->msgData.securityType );
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, this->msgResult );

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

    bool rpcMessageWifiSetting::deserialize(int fd)
        {
            uint16_t tmpValue;
            if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
                return false;
            }

            this->msgAction = app::rpcMessageWifiSettingActionType(tmpValue);

            switch (this->msgAction)
            {
                case app::rpcMessageWifiSettingActionType::GET_WIFI_SETTING:
                case app::rpcMessageWifiSettingActionType::EDIT_WIFI_SETTING:
                {
                    uint16_t presharedKey_size, ssid_size;

                    if (rpcMessage::recvInterruptRetry(fd, &presharedKey_size, sizeof(uint16_t)) != true) {
                        return false;
                    }

                    if(presharedKey_size > 0)
                    {
                        memset(this->msgData.presharedKey, 0, sizeof(this->msgData.presharedKey));
                        if (rpcMessage::recvInterruptRetry(fd, this->msgData.presharedKey, presharedKey_size) != true) {
                            return false;
                        }
                    }

                    if (rpcMessage::recvInterruptRetry(fd, &ssid_size, sizeof(uint16_t)) != true) {
                        return false;
                    }

                    if(ssid_size > 0)
                    {
                        memset(this->msgData.ssid, 0 , sizeof(this->msgData.ssid));
                        if (rpcMessage::recvInterruptRetry(fd, this->msgData.ssid, ssid_size) != true) {
                            return false;
                        }
                    }

                    if (rpcMessage::recvInterruptRetry(fd, &this->msgData.accessPoint, sizeof(uint16_t)) != true) {
                        return false;
                    }

                    if (rpcMessage::recvInterruptRetry(fd, &this->msgData.securityType, sizeof(uint16_t)) != true) {
                        return false;
                    }

                    if (rpcMessage::recvInterruptRetry(fd, &this->msgResult, sizeof(uint16_t)) != true) {
                        return false;
                    }

                    break;
                }
                default:
                    break;
            }

            return true;
        }


    app::rpcMessageWifiSettingActionType rpcMessageWifiSetting::getMsgAction() const
    {
        return this->msgAction;
    }

    void rpcMessageWifiSetting::setMsgAction(const rpcMessageWifiSettingActionType action)
    {
        this->msgAction = action;
    }

    app::rpcMessageWifiSettingResultType rpcMessageWifiSetting::getMsgResult() const
    {
        return this->msgResult;
    }

    void rpcMessageWifiSetting::setMsgResult(const rpcMessageWifiSettingResultType result)
    {
        this->msgResult = result;
    }

    app::rpcMessageWifiSettingData_t rpcMessageWifiSetting::getWifiSettingMsgData() const
    {
        return this->msgData;
    }

    void rpcMessageWifiSetting::setWifiSettingMsgData(const app::rpcMessageWifiSettingData_t msgData)
    {
        this->msgData = msgData;
    }

    std::string rpcMessageWifiSetting::wifiMsgResult2Str()
    {
        std::string outStr;

        switch(this->msgResult)
        {
            case app::rpcMessageWifiSettingResultType::PRESHAREDKEY_CHARACTER_INVALID:
                outStr = "Preshared key have character NOT allow";
                break;

            case app::rpcMessageWifiSettingResultType::PRESHAREDKEY_LENGTH_INVALID:
                outStr = "Preshared key have length NOT allow";
                break;

            case app::rpcMessageWifiSettingResultType::PRESHAREDKEY_IS_NULL:
                outStr = "Preshared key NOT null";
                break;

            case app::rpcMessageWifiSettingResultType::SSID_CHARACTER_INVALID:
                outStr = "SSID have character NOT allow";
                break;

            case app::rpcMessageWifiSettingResultType::SSID_LENGTH_INVALID:
                outStr = "SSID have length NOT allow";
                break;

            case app::rpcMessageWifiSettingResultType::SSID_IS_NULL:
                outStr = "SSID NOT null";
                break;

            case app::rpcMessageWifiSettingResultType::UNKNOWN_ERROR:
                outStr = "Unknow error";
                break;

            case app::rpcMessageWifiSettingResultType::SUCCEEDED:
                outStr = "Succeeded";
                break;
        }

        return outStr;
    }

}
