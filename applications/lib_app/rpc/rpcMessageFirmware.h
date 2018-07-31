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
        DO_UPGRADE,
        GET_INFO
    };

    typedef struct {
        app::firmwareStatusType status;
        app::firmwareResultType result;
        std::string             fwName;
        std::string             fwDesc;
        std::string             fwDate;
    } rpcMessageFirmwareData_t;

    class rpcMessageFirmware: public app::rpcMessage
    {
    public:
        virtual bool serialize(int fd);
        virtual bool deserialize(int fd);

        rpcMessageFirmware();
        virtual ~rpcMessageFirmware();

        std::string getFirmwareName();
        void        setFirmwareName(const std::string &filename);

        app::rpcMessageFirmwareData_t getFirmwareMsgData();
        void                          setFirmwareMsgData(const app::rpcMessageFirmwareData_t &msgData);

        app::rpcFirmwareActionType getFirmwareMsgAction();
        void                       setFirmwareMsgAction(const app::rpcFirmwareActionType &msgAction);

        static std::string statusToString(const app::firmwareStatusType &status);
        static std::string resultToString(const app::firmwareResultType &result);

    private:
        app::rpcFirmwareActionType msgAction;
        rpcMessageFirmwareData_t   msgData;
    };

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEFIRMWARE_H_ */
