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

    class rpcMessageFirmware: public app::rpcMessage
    {
    public:
        virtual bool serialize(int fd);
        virtual bool deserialize(int fd);

        rpcMessageFirmware();
        virtual ~rpcMessageFirmware();

        std::string getFirmwareName();
        void setFirmwareName(const std::string &filename);

        uint16_t getErrorNo();
        void setErrorNo(const uint16_t errNo);

    private:
        std::string firmware_name;
        uint16_t errNo;
    };

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEFIRMWARE_H_ */
