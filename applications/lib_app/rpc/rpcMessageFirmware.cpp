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
            rpcMessage(rpcMessageType::handle_firmware_action), rpc_info()
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

        switch (this->getFirmwareRpcInfo().action)
        {
            case app::rpcFirmwareActionType::GET_STATUS:
            {
                buff_len += sizeof(app::firmwareResultType);
                buff_len += sizeof(app::firmwareStatusType);

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->rpc_info.result);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->rpc_info.status);

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
                buff_len += this->firmware_name.length();

                std::unique_ptr<char> buff_ptr(new char[buff_len]());
                uint16_t tmpValue;

                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->rpc_info.result);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->rpc_info.status);
                tmpValue = this->firmware_name.length();
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, tmpValue);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->firmware_name);

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
                buff_len += this->rpc_info.fwInfo.created_date.length();
                buff_len += sizeof(uint16_t);
                buff_len += this->rpc_info.fwInfo.description.length();

                std::unique_ptr<char> buff_ptr(new char[buff_len]());
                uint16_t tmpValue;

                tmpValue = this->rpc_info.fwInfo.created_date.length();
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, tmpValue);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->rpc_info.fwInfo.created_date);
                tmpValue = this->rpc_info.fwInfo.description.length();
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, tmpValue);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->rpc_info.fwInfo.description);

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
        switch (this->getFirmwareRpcInfo().action)
        {
            case app::rpcFirmwareActionType::GET_STATUS:
            {
                if (rpcMessage::recvInterruptRetry(fd, &this->rpc_info.result, sizeof(app::firmwareResultType)) != true) {
                    return false;
                }
                if (rpcMessage::recvInterruptRetry(fd, &this->rpc_info.status, sizeof(app::firmwareStatusType)) != true) {
                    return false;
                }

                break;
            }
            case app::rpcFirmwareActionType::DO_UPGRADE:
            {
                uint16_t firmware_name_size;

                if (rpcMessage::recvInterruptRetry(fd, &this->rpc_info.result, sizeof(app::firmwareResultType)) != true) {
                    return false;
                }
                if (rpcMessage::recvInterruptRetry(fd, &this->rpc_info.status, sizeof(app::firmwareStatusType)) != true) {
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

                    this->firmware_name = buff_ptr.get();
                }
                break;
            }
            case app::rpcFirmwareActionType::GET_INFO:
            {
                uint16_t tmpValue;
                if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
                    return false;
                }

                if (tmpValue > 0) {
                    std::unique_ptr<char> buff_ptr(new char[tmpValue + 1]());

                    if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), tmpValue) != true) {
                        return false;
                    }

                    this->rpc_info.fwInfo.created_date = buff_ptr.get();
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

                    this->rpc_info.fwInfo.description = buff_ptr.get();
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
        this->firmware_name = filename;
    }

    std::string rpcMessageFirmware::getFirmwareName()
    {
        return this->firmware_name;
    }

    app::rpcMessageFirmware_t rpcMessageFirmware::getFirmwareRpcInfo()
    {
        return this->rpc_info;
    }

    void rpcMessageFirmware::setFirmwareRpcInfo(const rpcMessageFirmware_t &firmware_info)
    {
        this->rpc_info = firmware_info;
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
