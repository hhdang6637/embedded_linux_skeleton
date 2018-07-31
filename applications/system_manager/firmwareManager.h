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
        int                     currentFwNumber;
        pid_t                   pidChild;

        bool firmwareValidator(const char *filename);
        bool doFirmwareUpgrade();
        void loadCurrentFwinfo();

        static void handler(int sig);

    public:
        virtual                 ~firmwareManager();

        static firmwareManager* getInstance();
        void                    setFirmwareName(std::string &filename);
        std::string             getFirmwareName();
        app::firmwareStatusType getFirmwareStatus();
        app::firmwareResultType getFirmwareResult();
        std::string             getFirmwareDesc();
        std::string             getFirmwareDate();
        bool                    doAsynUpgrade();
    };

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_ */
