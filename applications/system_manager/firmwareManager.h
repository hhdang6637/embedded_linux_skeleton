/*
 * firmwareManager.h
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_
#define APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_

#include "string"

namespace app
{

    class firmwareManager
    {
    private:
        firmwareManager();
        static firmwareManager* s_instance;
        std::string firmware_name;

        bool firmwareValidator();

    public:
        virtual ~firmwareManager();

        static firmwareManager* getInstance();
        std::string getFirmwareName();

        void setFirmwareName(std::string &filename);

        uint16_t doFirmwareUpgrade();
    };

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_FIRMWAREMANAGER_H_ */
