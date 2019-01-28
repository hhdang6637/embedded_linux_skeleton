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
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/reboot.h>

#include <fstream>

#include "firmwareManager.h"
#include "utilities.h"
#include "conversion.h"
#include "fdt.h"

#define FIRMWARE_NAME_F             "/boot/firmware_%d"
#define FIRMWARE_SELECTED_PATH      "/boot/firmware_selected"

namespace app
{
    firmwareManager::firmwareManager() :
            status(app::firmwareStatusType::NONE),
            result(app::firmwareResultType::NONE),
            reboot(false),
            currentFwNumber(0),
            pidChild(-1)
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

            s_instance->loadCurrentFwinfo();
        }

        return s_instance;
    }

    std::string firmwareManager::getFirmwareName()
    {
        return this->fwName;
    }

    void firmwareManager::setFirmwareName(const std::string &filename)
    {
        this->fwName = filename;
    }

    void firmwareManager::setFirmwareReboot(const bool &reboot)
    {
        this->reboot = reboot;
    }

    app::firmwareStatusType firmwareManager::getFirmwareStatus()
    {
        return this->status;
    }

    app::firmwareResultType firmwareManager::getFirmwareResult()
    {
        return this->result;
    }

    std::string firmwareManager::getFirmwareDesc()
    {
        return this->fwDesc;
    }

    std::string firmwareManager::getFirmwareDate()
    {
        return this->fwDate;
    }

    void firmwareManager::loadCurrentFwinfo()
    {
        std::ifstream file(FIRMWARE_SELECTED_PATH);

        if (file.is_open()) {
            std::string line;
            while (getline(file, line)) {

                this->currentFwNumber = 0;

                if (line.length() > 0 && line[0] == '1') {
                    this->currentFwNumber = 1;
                }

            }
            file.close();
        } else {
            syslog(LOG_ERR, "cannot open file %s", FIRMWARE_SELECTED_PATH);
            return;
        }

        syslog(LOG_NOTICE, "We're using FwNumber : %d", this->currentFwNumber);

        char fw_name[32];
        snprintf(fw_name, sizeof(fw_name), FIRMWARE_NAME_F, this->currentFwNumber);

        long int size;
        struct fdt_header *header = (struct fdt_header*)::file_to_addr(fw_name, &size);

        char *desc;
        if (fit_get_desc((const fdt32_t *)header, 0, &desc) == 0) {
            syslog(LOG_NOTICE, "Fw desc: %s", desc);
            this->fwDesc = desc;
        }
        time_t timestamp;
        if (fit_get_timestamp((const fdt32_t *)header, 0, &timestamp) == 0) {
            syslog(LOG_NOTICE,"Fw created:%s", ctime(&timestamp));

            this->fwDate = time2String(timestamp);
        }

        if (header != NULL) {
            munmap(header, size);
        }
    }

    bool firmwareManager::firmwareValidator(const char *filename)
    {
        syslog(LOG_INFO, "Validating firmware....\n");

        long int size;

        struct fdt_header *header = (struct fdt_header*)::file_to_addr(filename, &size);

        bool rc = true;

        if (header == NULL) {
            syslog(LOG_INFO, "Can't read %s: %s\n", filename, strerror(errno));
            rc = false;
            goto out;
        }

        if (fdt_check_header(header) != 0) {
            syslog(LOG_INFO, "Firmware image invalid: bad firmware header\n");
            rc = false;
            goto out;
        }

        if ((long int)be32_to_cpu(header->totalsize) != size) {
            syslog(LOG_INFO, "Firmware image invalid: bad size\n");
            rc = false;
            goto out;
        }
out:

        if (header != NULL) {
            munmap(header, size);
        }

        return rc;
    }

    void firmwareManager::doSystemReboot()
    {
        ::sync();
        ::sleep(5);
        ::reboot(RB_AUTOBOOT);
    }

    bool firmwareManager::doFirmwareUpgrade()
    {
        std::ofstream file;
        bool rc = true;

        if (this->firmwareValidator(this->fwName.c_str()) == false) {
            syslog(LOG_INFO, "%s is not valid firmware\n", this->fwName.c_str());
            rc = false;
            goto doFirmwareUpgradeDone;
        }

        syslog(LOG_INFO, "Processing firmware upgrade....\n");

        char fw_name[32];
        snprintf(fw_name, sizeof(fw_name), FIRMWARE_NAME_F, this->currentFwNumber == 0 ? 1 : 0);

        if (::copy_file(this->fwName.c_str(), fw_name) == false) {
            syslog(LOG_ERR, "cannot copy success %s to %s", this->fwName.c_str(), fw_name);
            rc = false;
            goto doFirmwareUpgradeDone;
        }

        file.open(FIRMWARE_SELECTED_PATH, std::fstream::out | std::fstream::trunc);

        if (file.is_open()) {
            file << (this->currentFwNumber == 0 ? 1 : 0);
            file.close();
        }

doFirmwareUpgradeDone:
        ::unlink(this->fwName.c_str());
        syslog(LOG_INFO, "Processing firmware Done, removed %s\n", this->fwName.c_str());

        return rc;
    }

    void firmwareManager::handler(int sig)
    {
        pid_t pid;
        int wstatus;
        pid = wait(&wstatus);
        if (pid == firmwareManager::getInstance()->pidChild) {
            firmwareManager::getInstance()->status =  app::firmwareStatusType::DONE;
            if (wstatus == EXIT_SUCCESS) {
                firmwareManager::getInstance()->result = app::firmwareResultType::SUCCEEDED;
                if (firmwareManager::getInstance()->reboot) {
                    syslog(LOG_INFO, "Rebooting...");
                    firmwareManager::getInstance()->doSystemReboot();
                }
            } else {
                firmwareManager::getInstance()->result = app::firmwareResultType::FAILED;
            }
            firmwareManager::getInstance()->pidChild = -1;
        }
    }

    bool firmwareManager::doAsynUpgrade()
    {
        this->status = app::firmwareStatusType::IN_PROGRESS;
        // clear old result
        this->result = app::firmwareResultType::NONE;

        struct sigaction sa;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sa.sa_handler = firmwareManager::handler;
        if (sigaction(SIGCHLD, &sa, NULL) == -1) {
            syslog(LOG_ERR, "cannot register SIGCHLD handler");
            return false;
        }

        switch ((this->pidChild = fork())) {
        case -1: {
            syslog(LOG_ERR, "cannot fork to upgrade firmware");
            this->status = app::firmwareStatusType::DONE;
            this->result = app::firmwareResultType::FAILED;
            return false;
        }
        case 0: {
            if (firmwareManager::doFirmwareUpgrade() == true) {
                exit(EXIT_SUCCESS);
            } else {
                exit(EXIT_FAILURE);
            }
            break;
        }

        default:
            break;
        }

        syslog(LOG_INFO, "the firmware upgrade proccess is handled by process %d\n", this->pidChild);

        return true;
    }

} /* namespace app */
