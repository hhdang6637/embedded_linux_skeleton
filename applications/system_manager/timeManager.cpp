/*
 * timeManager.cpp
 *
 *  Created on: Jan 19, 2019
 *      Author: nmhien
 */
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <string.h>

#include "rpcMessageTime.h"
#include "timeManager.h"
#include "utilities.h"

#define NTP_PERSISTENT_CONFIG   "/data/ntp.conf"
#define NTP_CONFIG_FILE "/tmp/configs/ntp.conf"
#define NTP_PID_FILE    "/var/run/ntpd.pid"

static app::ntpConfig_t ntpCfg;

static bool buildNtpConfigFile()
{
    std::ofstream ntp_config_file(NTP_CONFIG_FILE);

    if(ntp_config_file.is_open()) {
        ntp_config_file << "server " << ntpCfg.ntp_server0 << "\n"
                        << "server " << ntpCfg.ntp_server1 << "\n"
                        << "server " << ntpCfg.ntp_server2 << "\n"
                        << "server " << ntpCfg.ntp_server3 << "\n";
        ntp_config_file.close();
        return true;
    }

    return false;
}

static void setNtpCfgDefault(app::ntpConfig_t *cfg)
{
    string_copy(cfg->ntp_server0, "0.asia.pool.ntp.org");
    string_copy(cfg->ntp_server1, "1.asia.pool.ntp.org");
    string_copy(cfg->ntp_server2, "2.asia.pool.ntp.org");
    string_copy(cfg->ntp_server3, "3.asia.pool.ntp.org");
}

static void stopNtp()
{
    // verify pid file and stop openvpn service
    char cmd[32];
    pid_t ntp_pid;

    ntp_pid = get_pid_from_pidfile(NTP_PID_FILE);
    if (ntp_pid != -1) {
        snprintf(cmd, 32, "kill %d", ntp_pid);
        system(cmd);
        sleep(1);
    }
}


static bool startNtp()
{
    if(system("/usr/sbin/ntpd -g -c " NTP_CONFIG_FILE " -p " NTP_PID_FILE) != 0) {
        syslog(LOG_ERR, "Cannot start NTP service");
        return false;
    }

    return false;
}

static bool setNtpCfg(const app::ntpConfig_t cfg)
{
    // TODO validate cfg
    if (::memcmp(&cfg, &ntpCfg, sizeof(app::ntpConfig_t)) != 0) {
        stopNtp();
        memcpy(&ntpCfg, &cfg, sizeof(cfg));

        if (cfg.state == app::stateType::ENABLE) {
            if (buildNtpConfigFile() == true) {
                return startNtp();
            } else {
                return false;
            }
        }
    }

    return true;
}

static bool setSystemTime(const struct tm &date_time)
{
    tm tmp_date_time;
    memcpy(&tmp_date_time, &date_time, sizeof(date_time));
    // disable NTP
    ntpCfg.state = app::stateType::DISABLE;
    stopNtp();

    if(mktime(&tmp_date_time) == -1) {
        return false;
    }

    return true;
}

static bool time_cfg_handler (int socket_fd)
{
    app::rpcMessageTime msg;

    if (msg.deserialize(socket_fd)) {
        switch (msg.getMsgAction())
        {
            case app::rpcMessageTimeActionType::GET_SYSTEM_TIME:
            {
                time_t t = time(NULL);

                msg.setSystemTime(*localtime(&t));
                msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                break;
            }
            case app::rpcMessageTimeActionType::SET_SYSTEM_TIME:
            {
                if (setSystemTime(msg.getSystemTime()) == true) {
                    msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                } else {
                    msg.setMsgResult(app::rpcMessageTimeResultType::FAILED);
                }

                break;
            }
            case app::rpcMessageTimeActionType::GET_NTP_CONFIG:
            {
                msg.setNtpCfg(ntpCfg);
                msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);

                break;
            }
            case app::rpcMessageTimeActionType::SET_NTP_CONFIG:
            {
                if (setNtpCfg(msg.getNtpCfg()) == true) {
                    msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                } else {
                    msg.setMsgResult(app::rpcMessageTimeResultType::FAILED);
                }

                break;
            }
        }
    }

    return msg.serialize(socket_fd);
}

void timeManager_init(app::rpcUnixServer &rpcServer)
{
    setNtpCfgDefault(&ntpCfg);
    rpcServer.registerMessageHandler(app::rpcMessage::rpcMessageType::handle_time_cfg, time_cfg_handler);
}

