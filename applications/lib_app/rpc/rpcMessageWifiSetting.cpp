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

                buff_len += sizeof(uint16_t) + this->msgData.presharedKey.length();
                buff_len += sizeof(uint16_t) + this->msgData.ssid.length();
                buff_len += sizeof(uint16_t); // this->msgData.accessPoint;
                buff_len += sizeof(uint16_t); // this->msgData.securityType;
                buff_len += sizeof(uint16_t); // this->msgResult;

                std::unique_ptr<char> buff_ptr(new char[buff_len]);

                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->msgData.presharedKey );
                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->msgData.ssid);
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
                        std::unique_ptr<char> buff_ptr(new char[presharedKey_size + 1]);
                        if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), presharedKey_size) != true) {
                            return false;
                        }
                        this->msgData.presharedKey = buff_ptr.get();
                    }

                    if (rpcMessage::recvInterruptRetry(fd, &ssid_size, sizeof(uint16_t)) != true) {
                        return false;
                    }

                    if(ssid_size > 0)
                    {
                        std::unique_ptr<char> buff_ptr(new char[ssid_size + 1]);
                        if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), ssid_size) != true) {
                            return false;
                        }
                        this->msgData.ssid = buff_ptr.get();
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

    static inline rpcMessageWifiSettingResultType validateSsid(const char* _ssid)
    {
        const char* specialKeyAllow = " .-_";
        char *c = NULL;
        int i = 0;
        int lengthSsid = 0;

        if(_ssid == NULL) {
            return app::rpcMessageWifiSettingResultType::SSID_IS_NULL;
        }

        lengthSsid = strlen(_ssid);

        if(lengthSsid > 32){
            return app::rpcMessageWifiSettingResultType::SSID_LENGTH_INVALID;
        }

        for(; i < lengthSsid; i++) {

            c = (char*) strchr(specialKeyAllow, _ssid[i]);

            if(c == NULL) {
                //in range [0-9]
                if(_ssid[i] >= '0' && _ssid[i] <= '9') {
                    continue;
                }

                //in range [A-F]
                if(_ssid[i] >= 'A' && _ssid[i] <= 'F') {
                    continue;
                }

                //in range[a-f]
                if(_ssid[i] >= 'a' && _ssid[i] <= 'f') {
                    continue;
                }

                return app::rpcMessageWifiSettingResultType::SSID_CHARACTER_INVALID;
            }
        }

        return app::rpcMessageWifiSettingResultType::SUCCEEDED;
    }

    static inline rpcMessageWifiSettingResultType validatePresharedKey(const char* pwd)
    {
        int i = 0;
        int lengthPwd = 0;

        if(pwd == NULL) {
            return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_IS_NULL;
        }

        lengthPwd = strlen(pwd);

        if(lengthPwd < 8 || lengthPwd > 64) {
            return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_LENGTH_INVALID;
        }

        for(i = 0; i < lengthPwd; i++) {
            //in range [0-9]
            if(pwd[i] >= '0' && pwd[i] <= '9') {
                continue;
            }

            if(lengthPwd == 64) {
                //in range [A-F]
                if(pwd[i] >= 'A' && pwd[i] <= 'F') {
                    continue;
                }

                //in range[a-f]
                if(pwd[i] >= 'a' && pwd[i] <= 'f') {
                    continue;
                }

            } else {
                //in range [A-Z]
                if(pwd[i] >= 'A' && pwd[i] <= 'Z') {
                    continue;
                }

                //in range[a-z]
                if(pwd[i] >= 'a' && pwd[i] <= 'z') {
                    continue;
                }
            }

            return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_CHARACTER_INVALID;
        }

        return app::rpcMessageWifiSettingResultType::SUCCEEDED;
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
