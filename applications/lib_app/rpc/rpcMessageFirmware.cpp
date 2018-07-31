/*
 * rpcMessageFirmware.cpp
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */
#include <syslog.h>
#include <memory>

#include "rpcMessageFirmware.h"

namespace app
{

    rpcMessageFirmware::rpcMessageFirmware() :
            rpcMessage(rpcMessageType::handle_firmware_action),
            msgAction(app::rpcFirmwareActionType::GET_INFO),
            msgData()
    {
    }

    rpcMessageFirmware::~rpcMessageFirmware()
    {
        // TODO Auto-generated destructor stub
    }

    bool rpcMessageFirmware::serialize(int fd)
    {
        int buff_len = 0;
        int offset = 0;
        uint16_t tmpValue;

        tmpValue = (uint16_t)this->msgAction;
        if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        switch (this->msgAction)
        {
            case app::rpcFirmwareActionType::GET_STATUS:
            {
                buff_len += sizeof(app::firmwareResultType);
                buff_len += sizeof(app::firmwareStatusType);

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgData.result);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgData.status);

                if (buff_len != offset) {

                    char buff[256];
                    snprintf(buff, sizeof(buff), "%s-%u something wrong happened", __FUNCTION__, __LINE__);
                    syslog(LOG_ERR, buff);
                    return false;

                }

                if (rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
                    return false;
                }
                break;
            }
            case app::rpcFirmwareActionType::DO_UPGRADE:
            {
                buff_len += sizeof(app::firmwareResultType);
                buff_len += sizeof(app::firmwareStatusType);
                buff_len += sizeof(uint16_t);
                buff_len += this->msgData.fwName.length();

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgData.result);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgData.status);
                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->msgData.fwName);

                if (buff_len != offset) {

                    char buff[256];
                    snprintf(buff, sizeof(buff), "%s-%u something wrong happened", __FUNCTION__, __LINE__);
                    syslog(LOG_ERR, buff);
                    return false;

                }

                if (rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
                    return false;
                }
                break;
            }
            case app::rpcFirmwareActionType::GET_INFO:
            {
                buff_len += sizeof(uint16_t);
                buff_len += this->msgData.fwDate.length();
                buff_len += sizeof(uint16_t);
                buff_len += this->msgData.fwDesc.length();

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->msgData.fwDate);
                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->msgData.fwDesc);

                if (buff_len != offset) {

                    char buff[256];
                    snprintf(buff, sizeof(buff), "%s-%u something wrong happened", __FUNCTION__, __LINE__);
                    syslog(LOG_ERR, buff);
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

    bool rpcMessageFirmware::deserialize(int fd)
    {
        uint16_t tmpValue;
        if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        this->msgAction = app::rpcFirmwareActionType(tmpValue);

        switch (this->msgAction)
        {
            case app::rpcFirmwareActionType::GET_STATUS:
            {
                if (rpcMessage::recvInterruptRetry(fd, &this->msgData.result, sizeof(app::firmwareResultType)) != true) {
                    return false;
                }
                if (rpcMessage::recvInterruptRetry(fd, &this->msgData.status, sizeof(app::firmwareStatusType)) != true) {
                    return false;
                }

                break;
            }
            case app::rpcFirmwareActionType::DO_UPGRADE:
            {
                uint16_t firmware_name_size;

                if (rpcMessage::recvInterruptRetry(fd, &this->msgData.result, sizeof(app::firmwareResultType)) != true) {
                    return false;
                }
                if (rpcMessage::recvInterruptRetry(fd, &this->msgData.status, sizeof(app::firmwareStatusType)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &firmware_name_size, sizeof(firmware_name_size)) != true) {
                    return false;
                }

                if (firmware_name_size > 0) {
                    std::unique_ptr<char> buff_ptr(new char[firmware_name_size + 1]());

                    if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), firmware_name_size) != true) {
                        return false;
                    }

                    this->msgData.fwName = buff_ptr.get();
                }
                break;
            }
            case app::rpcFirmwareActionType::GET_INFO:
            {

                if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
                    return false;
                }

                if (tmpValue > 0) {
                    std::unique_ptr<char> buff_ptr(new char[tmpValue + 1]());

                    if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), tmpValue) != true) {
                        return false;
                    }

                    this->msgData.fwDate = buff_ptr.get();
                }

                tmpValue = 0;

                if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
                    return false;
                }

                if (tmpValue > 0) {
                    std::unique_ptr<char> buff_ptr(new char[tmpValue + 1]());

                    if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), tmpValue) != true) {
                        return false;
                    }

                    this->msgData.fwDesc = buff_ptr.get();
                }
                break;
            }
            default:
                break;
        }

        return true;
    }

    void rpcMessageFirmware::setFirmwareName(const std::string &filename)
    {
        this->msgData.fwName = filename;
    }

    std::string rpcMessageFirmware::getFirmwareName()
    {
        return this->msgData.fwName;
    }

    app::rpcMessageFirmwareData_t rpcMessageFirmware::getFirmwareMsgData()
    {
        return this->msgData;
    }

    void rpcMessageFirmware::setFirmwareMsgData(const app::rpcMessageFirmwareData_t &msgData)
    {
        this->msgData = msgData;
    }

    app::rpcFirmwareActionType rpcMessageFirmware::getFirmwareMsgAction()
    {
        return this->msgAction;
    }

    void rpcMessageFirmware::setFirmwareMsgAction(const app::rpcFirmwareActionType &msgAction)
    {
        this->msgAction = msgAction;
    }

    std::string rpcMessageFirmware::statusToString(const app::firmwareStatusType &status)
    {
        std::string outStr;

        switch(status)
        {
            case app::firmwareStatusType::NONE:
                outStr = "None";
                break;

            case app::firmwareStatusType::IN_PROGRESS:
                outStr = "In-progress";
                break;

            case app::firmwareStatusType::DONE:
                outStr = "Done";
                break;
        }

        return outStr;
    }

    std::string rpcMessageFirmware::resultToString(const app::firmwareResultType &result)
    {
        std::string outStr;

        switch(result)
        {
            case app::firmwareResultType::NONE:
                outStr = "None";
                break;

            case app::firmwareResultType::FAILED:
                outStr = "Failed";
                break;

            case app::firmwareResultType::SUCCEEDED:
                outStr = "Succeeded";
                break;
        }

        return outStr;
    }

} /* namespace app */
