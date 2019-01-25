/*
 * timeManager.cpp
 *
 *  Created on: Jan 19, 2019
 *      Author: nmhien
 */
#include <time.h>

#include "rpcMessageTime.h"
#include "timeManager.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include "utilities.h"

#define NTP_PERSISTENT_CONFIG   "/data/ntp.conf"
#define NTP_CONFIG_DIR  "/tmp/ntp/"
#define NTP_PID_FILE    "/var/run/ntpd.pid"

static app::ntpConfig_t ntpCfg;

static bool configChange(const app::ntpConfig_t newCfg, const app::ntpConfig_t oldCfg)
{
    if(newCfg.state != oldCfg.state)
        return true;

    if(strcmp(newCfg.ntp_server, oldCfg.ntp_server) != 0 && strlen(newCfg.ntp_server) != 0)
        return true;

    if(strcmp(newCfg.ntp_server1, oldCfg.ntp_server1) != 0 && strlen(newCfg.ntp_server1) != 0)
        return true;

    if(strcmp(newCfg.ntp_server2, oldCfg.ntp_server2) != 0 && strlen(newCfg.ntp_server2) != 0)
        return true;

    if(strcmp(newCfg.ntp_server3, oldCfg.ntp_server3) != 0 && strlen(newCfg.ntp_server3) != 0)
        return true;

    return false;
}

static bool initNtp()
{
    mkdir(NTP_CONFIG_DIR, 0755);
    std::ofstream ntp_config_file(NTP_CONFIG_DIR"ntp.conf");

    if(ntp_config_file.is_open())
    {
        ntp_config_file << "server " << ntpCfg.ntp_server << "\n"
                        << "server " << ntpCfg.ntp_server1 << "\n"
                        << "server " << ntpCfg.ntp_server2 << "\n"
                        << "server " << ntpCfg.ntp_server3 << "\n";
        ntp_config_file.close();
    }

    return true;
}

static bool setNtpCfgDefault(app::ntpConfig_t *cfg)
{
    strncpy(cfg->ntp_server, "0.asia.pool.ntp.org", strlen("0.asia.pool.ntp.org"));
    strncpy(cfg->ntp_server1, "1.asia.pool.ntp.org", strlen("1.asia.pool.ntp.org"));
    strncpy(cfg->ntp_server2, "2.asia.pool.ntp.org", strlen("2.asia.pool.ntp.org"));
    strncpy(cfg->ntp_server3, "3.asia.pool.ntp.org", strlen("3.asia.pool.ntp.org"));
    return true;
}

static bool stopNtp()
{
    // verify pid file and stop ntpd service
    if (access("/var/run/ntpd.pid", F_OK) != -1) {
        if(system("killall ntpd") == 0)
            return true;
    }
    return false;
}


static bool startNtp()
{
    std::string command;
    command = "/usr/sbin/ntpd -g -c " NTP_CONFIG_DIR "ntp.conf -p " NTP_PID_FILE;

    if(system(command.c_str()) == 0)
        return true;

    return false;
}

static bool setNtpCfg(const app::ntpConfig_t cfg)
{
    // TODO validate cfg
    bool result_start = false;
    if(configChange(cfg, ntpCfg) == true)
    {
        stopNtp();
        memset(&ntpCfg, 0, sizeof(ntpCfg));
        memcpy(&ntpCfg, &cfg, sizeof(cfg));
    }

    if(cfg.state != 0)
    {
        if( initNtp() == true)
            result_start = startNtp();
    }

    return result_start;
}

static app::ntpConfig_t getNtpCfg()
{
    return ntpCfg;
}

static bool setSystemTime(const struct tm &date_time)
{
    // Command set date: date +%Y%m%d -s "20120418"
    // command set time: date +%T -s "11:14:00"
    char cmd_set_date[30];
    char date[11];
    char cmd_set_time[30];
    char _time[6];

    stopNtp();

    strftime(date, sizeof(date), "%Y-%m-%d", &date_time);
    snprintf(cmd_set_date, sizeof(cmd_set_date),"date  --s \"%s\"",date);

    strftime(_time, sizeof(_time), "%H:%M", &date_time);
    snprintf(cmd_set_time, sizeof(cmd_set_time),"date --s \"%s\"",_time);

    if( (system(cmd_set_date) != 0) ||
        (system(cmd_set_time) != 0) )
    {
        return false;
    }
    syslog(LOG_INFO,"setSystemTime: date %s time: %s", date, _time);
    return true;
}

static struct tm getSystemTime()
{
    time_t t = time(NULL);
    tm sysTime = *localtime(&t);
    return sysTime;
}

static bool time_cfg_handler (int socket_fd)
{
    app::rpcMessageTime msg;

    if (msg.deserialize(socket_fd)) {
        switch (msg.getMsgAction())
        {
            case app::rpcMessageTimeActionType::GET_SYSTEM_TIME:
            {
                msg.setSystemTime(getSystemTime());
                msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                break;
            }
            case app::rpcMessageTimeActionType::SET_SYSTEM_TIME:
            {
                ntpCfg.state = 0;
                bool result = setSystemTime(msg.getSystemTime());
                if(result == true)
                {
                    msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                }
                else
                {
                    msg.setMsgResult(app::rpcMessageTimeResultType::FAILED);
                }

                break;
            }
            case app::rpcMessageTimeActionType::GET_NTP_CONFIG:
            {
                msg.setNtpCfg(getNtpCfg());
                msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                break;
            }
            case app::rpcMessageTimeActionType::SET_NTP_CONFIG:
            {
                bool result = setNtpCfg(msg.getNtpCfg());
                if(result == true)
                {
                    msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                }
                else
                {
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

