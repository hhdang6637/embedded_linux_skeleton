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

        static firmwareManager* s_instance;
        app::firmwareStatusType status;
        app::firmwareResultType result;
        std::string             fwName;
        std::string             fwDesc;
        std::string             fwDate;
        bool                    reboot;
        int                     currentFwNumber;
        pid_t                   pidChild;

        bool firmwareValidator(const char *filename);
        void doSystemReboot();
        bool doFirmwareUpgrade();
        void loadCurrentFwinfo();

        static void handler(int sig);

    public:
        virtual                 ~firmwareManager();

        static firmwareManager* getInstance();
        void                    setFirmwareName(const std::string &filename);
        void                    setFirmwareReboot(const bool &reboot);
        std::string             getFirmwareName();
        app::firmwareStatusType getFirmwareStatus();
        app::firmwareResultType getFirmwareResult();
        std::string             getFirmwareDesc();
        std::string             getFirmwareDate();
        bool                    doAsynUpgrade();
    };

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_ */
