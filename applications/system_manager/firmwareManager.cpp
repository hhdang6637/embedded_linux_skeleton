/*
 * firmwareManager.cpp
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */
#include <iostream>

#include "firmwareManager.h"

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

    /**
     * return 0 on success, else return a specific code
     */
    uint16_t firmwareManager::doFirmwareUpgrade()
    {
        std::cout << "Checking firmware header....\n";

        std::cout << "this->firmware_name: " << this->firmware_name << std::endl;

        std::cout << "Processing firmware upgrade....\n";

        return 0;
    }

} /* namespace app */
