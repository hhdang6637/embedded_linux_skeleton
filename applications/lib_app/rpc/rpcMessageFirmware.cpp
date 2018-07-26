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
            rpcMessage(rpcMessageType::handle_firmware_action), errNo(0)
    {
    }

    rpcMessageFirmware::~rpcMessageFirmware()
    {
        // TODO Auto-generated destructor stub
    }

    bool rpcMessageFirmware::serialize(int fd)
    {
        // just write the state
        int buff_len = sizeof(uint16_t) + sizeof(uint16_t) + this->firmware_name.length();
        std::unique_ptr<char> buff_ptr(new char[buff_len]);

        int offset = 0;
        uint16_t tmpValue;

        tmpValue = this->errNo;
        offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, tmpValue);

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

        return true;
    }

    bool rpcMessageFirmware::deserialize(int fd)
    {
        uint16_t firmware_name_size;
        uint16_t errorNo;

        if (rpcMessage::recvInterruptRetry(fd, &errorNo, sizeof(errorNo)) != true) {
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

        this->errNo = errorNo;

        return true;
    }

    std::string rpcMessageFirmware::getFirmwareName()
    {
        return this->firmware_name;
    }

    void rpcMessageFirmware::setFirmwareName(const std::string &filename)
    {
        this->firmware_name = filename;
    }

    void rpcMessageFirmware::setErrorNo(const uint16_t errNo)
    {
        this->errNo = errNo;
    }

    uint16_t rpcMessageFirmware::getErrorNo()
    {
        return this->errNo;
    }

} /* namespace app */
