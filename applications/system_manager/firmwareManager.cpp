/*
 * firmwareManager.cpp
 *
 *  Created on: Jul 26, 2018
 *      Author: nmhien
 */
#include <iostream>

#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "firmwareManager.h"
#include "utilities.h"

#define FIRMWARE_NAME               "/boot/firmware_0"
#define FDT_MAGIC                   0xd00dfeed  /* 4: version, 4: total size */
#define FDT_SW_MAGIC                (~FDT_MAGIC)
#define FDT_FIRST_SUPPORTED_VERSION 0x10
#define FDT_LAST_SUPPORTED_VERSION  0x11

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

    bool firmwareManager::firmwareValidator(const char *filename)
    {
        syslog(LOG_INFO, "Validating firmware....\n");

        struct stat sbuf;
        firmware_header *header = (firmware_header *)MAP_FAILED;

        bool rc = true;

        int ifd = ::open(filename, O_RDONLY);

        if (ifd < 0) {
            syslog(LOG_INFO, "Can't open %s: %s\n", filename, strerror(errno));
            rc = false;
            goto out;
        }

        if (::fstat(ifd, &sbuf) < 0) {
            syslog(LOG_INFO, "Can't stat %s: %s\n", filename, strerror(errno));
            rc = false;
            goto out;
        }

        header = (firmware_header *) ::mmap(0, sizeof(header), PROT_READ, MAP_SHARED, ifd, 0);
        if (header == MAP_FAILED) {
            syslog(LOG_INFO, "Can't read %s: %s\n", filename, strerror(errno));
            rc = false;
            goto out;
        }

        if (be32_to_cpu(header->magic) == FDT_MAGIC) {

            /* Complete tree */
            if (be32_to_cpu(header->version) < FDT_FIRST_SUPPORTED_VERSION) {
                syslog(LOG_INFO, "Firmware image invalid: bad version\n");
                //-FDT_ERR_BADVERSION;
                rc = false;
                goto out;
            }

            if (be32_to_cpu(header->last_comp_version) > FDT_LAST_SUPPORTED_VERSION) {
                syslog(LOG_INFO, "Firmware image invalid: bad version\n");
                //-FDT_ERR_BADVERSION;
                rc = false;
                goto out;
            }

        } else if (be32_to_cpu(header->magic) == FDT_SW_MAGIC) {
            /* Unfinished sequential-write blob */
            if (be32_to_cpu(header->size_dt_struct) == 0) {
                syslog(LOG_INFO, "Firmware image invalid: bad state\n");
                // -FDT_ERR_BADSTATE;
                rc = false;
                goto out;
            }

        } else {
            syslog(LOG_INFO, "Firmware image invalid: bad magic\n");
            //-FDT_ERR_BADMAGIC;
            rc = false;
            goto out;
        }

        if (be32_to_cpu(header->totalsize) != (uint32_t) sbuf.st_size) {
            syslog(LOG_INFO, "Firmware image invalid: bad size\n");
            rc = false;
            goto out;
        }
out:
        if (ifd != -1) {
            close (ifd);
        }

        if (header != MAP_FAILED) {
            munmap(header, sizeof(header));
        }

        return rc;
    }

    /**
     * return 0 on success, else return a specific code
     */
    uint16_t firmwareManager::doFirmwareUpgrade()
    {
        if (this->firmwareValidator(this->firmware_name.c_str()) == false)
            return 1;

        syslog(LOG_INFO, "Processing firmware upgrade....\n");

        if (::copy_file(this->firmware_name.c_str(), FIRMWARE_NAME) == false) {
            syslog(LOG_ERR, "cannot copy success %s to %s", this->firmware_name.c_str(), FIRMWARE_NAME);
            return 1;
        }

        return 0;
    }

} /* namespace app */
