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
            rpcMessage(rpcMessageType::handle_firmware_action), firmware_info()
    {
    }

    rpcMessageFirmware::~rpcMessageFirmware()
    {
        // TODO Auto-generated destructor stub
    }

    bool rpcMessageFirmware::serialize(int fd)
    {
        // just write the state
        int buff_len = sizeof(rpcMessageFirmware_t) + sizeof(uint16_t) + this->firmware_name.length();
        std::unique_ptr<char> buff_ptr(new char[buff_len]);

        int offset = 0;
        uint16_t tmpValue;
        tmpValue = this->firmware_name.length();

        offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->firmware_info);
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

        return true;
    }

    bool rpcMessageFirmware::deserialize(int fd)
    {
        uint16_t firmware_name_size;

        if (rpcMessage::recvInterruptRetry(fd, &this->firmware_info, sizeof(this->firmware_info)) != true) {
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

    app::rpcMessageFirmware_t rpcMessageFirmware::getFirmwareInfo()
    {
        return this->firmware_info;
    }

    void rpcMessageFirmware::setFirmwareInfo(const rpcMessageFirmware_t &firmware_info)
    {
        this->firmware_info = firmware_info;
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
