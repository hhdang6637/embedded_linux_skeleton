/*
 * rpcMessageFirmware.h
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEFIRMWARE_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEFIRMWARE_H_

#include "rpcMessage.h"

namespace app
{
    enum class firmwareStatusType : uint16_t
    {
        NONE,
        IN_PROGRESS,
        DONE
    };

    enum class firmwareResultType : uint16_t
    {
        NONE,
        SUCCEEDED,
        FAILED
    };

    enum class rpcFirmwareActionType : uint16_t
    {
        GET_STATUS,
        DO_UPGRADE
    };

    typedef struct {
        app::rpcFirmwareActionType action;
        app::firmwareStatusType    status;
        app::firmwareResultType    result;
    }__attribute__((packed)) rpcMessageFirmware_t;

    class rpcMessageFirmware: public app::rpcMessage
    {
    public:
        virtual bool serialize(int fd);
        virtual bool deserialize(int fd);

        rpcMessageFirmware();
        virtual ~rpcMessageFirmware();

        std::string getFirmwareName();
        void setFirmwareName(const std::string &filename);

        rpcMessageFirmware_t getFirmwareInfo();
        void setFirmwareInfo(const rpcMessageFirmware_t &filename);

    private:
        std::string          firmware_name;
        rpcMessageFirmware_t firmware_info;
    };

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEFIRMWARE_H_ */
