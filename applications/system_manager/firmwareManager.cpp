/*
 * firmwareManager.cpp
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */
#include <iostream>

#include <syslog.h>

#include "firmwareManager.h"
#include "utilities.h"

#define FIRMWARE_NAME "/boot/firmware_0"

namespace app
{

    firmwareManager::firmwareManager()
    {
        // TODO Auto-generated constructor stub

    }

    firmwareManager::~firmwareManager()
    {
        // TODO Auto-generated destructor stub
    }

    firmwareManager *firmwareManager::s_instance = 0;

    firmwareManager* firmwareManager::getInstance()
    {
        if (s_instance == 0) {
            s_instance = new firmwareManager();
        }

        return s_instance;
    }

    std::string firmwareManager::getFirmwareName()
    {
        return this->firmware_name;
    }

    void firmwareManager::setFirmwareName(std::string &filename)
    {
        this->firmware_name = filename;
    }

    bool firmwareManager::firmwareValidator()
    {
        syslog(LOG_INFO, "Validating firmware....\n");

        return true;
    }

    /**
     * return 0 on success, else return a specific code
     */
    uint16_t firmwareManager::doFirmwareUpgrade()
    {
        if (this->firmwareValidator() == false)
            return 1;

        syslog(LOG_INFO, "Processing firmware upgrade....\n");

        if (::copy_file(this->firmware_name.c_str(), FIRMWARE_NAME) == false)
            return 1;

        return 0;
    }

} /* namespace app */
