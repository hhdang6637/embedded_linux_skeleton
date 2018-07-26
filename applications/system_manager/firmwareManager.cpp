/*
 * firmwareManager.cpp
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */
#include <iostream>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <syslog.h>

#include "firmwareManager.h"

#define FIRMWARE_NAME "/mnt/fw_0"

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

    static bool copy_file(const char *src, const char*dst)
    {
        int src_fd, dst_fd;
        struct stat statbuf;
        bool rc = false;

        src_fd = ::open(src, O_RDONLY);

        dst_fd = ::creat(dst, S_IRUSR | S_IWUSR);

        if (src_fd != -1 && dst_fd != -1 && ::fstat(src_fd, &statbuf) == 0) {
            if (::sendfile(dst_fd, src_fd, NULL, statbuf.st_size) == statbuf.st_size) {
                rc = true;
            }
        }

        if (src_fd != -1)
            close(src_fd);

        if (dst_fd != -1)
            close(dst_fd);

        return rc;
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
        if (firmwareValidator() == false)
            return 1;

        syslog(LOG_INFO, "Processing firmware upgrade....\n");

        if (copy_file(this->firmware_name.c_str(), FIRMWARE_NAME) == false)
            return 1;

        return 0;
    }

} /* namespace app */
