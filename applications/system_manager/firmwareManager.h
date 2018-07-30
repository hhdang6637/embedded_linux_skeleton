/*
 * firmwareManager.h
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_
#define APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_

#include "string"

#include "rpcMessageFirmware.h"

namespace app
{
    class firmwareManager
    {
    private:
        firmwareManager();

        std::string firmware_name;
        app::firmwareStatusType status;
        app::firmwareResultType result;

        bool firmwareValidator(const char *filename);

        bool doFirmwareUpgrade();

        int currentFwNumber;
        void loadCurrentFwinfo();

        static firmwareManager* s_instance;

        pid_t pidChild;
        static void handler(int sig);

    public:
        virtual ~firmwareManager();

        static firmwareManager* getInstance();

        std::string getFirmwareName();
        void setFirmwareName(std::string &filename);

        app::firmwareStatusType getFirmwareStatus();
        app::firmwareResultType getFirmwareResult();

        bool doAsynUpgrade();
    };

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_ */
