/*
 * timeManager.cpp
 *
 *  Created on: Jan 19, 2019
 *      Author: nmhien
 */
#include <time.h>

#include "rpcMessageTime.h"
#include "timeManager.h"
#include "serviceNtp.h"

static tm sysTime;

static bool setSystemTime(const struct tm &_time)
{
    // TODO set system time
    memset(&sysTime, 0, sizeof(sysTime));
    memcpy(&sysTime, &_time, sizeof(_time));
    return true;
}

static struct tm getSystemTime()
{
    time_t t = time(NULL);
    sysTime = *localtime(&t);
    syslog(LOG_INFO, "getSystemTime: time: H=%d M=%d\n", sysTime.tm_hour, sysTime.tm_min);
    syslog(LOG_INFO, "getSystemTime: date: d=%d m=%d y=%d\n", sysTime.tm_mday, sysTime.tm_mon, sysTime.tm_year);
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
                syslog(LOG_INFO, "time_cfg_handler:GET_SYSTEM_TIME: time: H=%d M=%d\n", msg.getSystemTime().tm_hour, msg.getSystemTime().tm_min);
                syslog(LOG_INFO, "time_cfg_handler:GET_SYSTEM_TIME: date: d=%d m=%d y=%d\n", msg.getSystemTime().tm_mday, msg.getSystemTime().tm_mon, msg.getSystemTime().tm_year);
                break;
            }
            case app::rpcMessageTimeActionType::SET_SYSTEM_TIME:
            {
                syslog(LOG_INFO, "time_cfg_handler:SET_SYSTEM_TIME: time: H=%d M=%d\n", msg.getSystemTime().tm_hour, msg.getSystemTime().tm_min);
                syslog(LOG_INFO, "time_cfg_handler:SET_SYSTEM_TIME: date: d=%d m=%d y=%d\n", msg.getSystemTime().tm_mday, msg.getSystemTime().tm_mon, msg.getSystemTime().tm_year);
                setSystemTime(msg.getSystemTime());
                msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                break;
            }
            case app::rpcMessageTimeActionType::GET_NTP_CONFIG:
            {
                msg.setNtpCfg(app::serviceNtp::getInstance()->getNtpCfg());
                msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                syslog(LOG_INFO, "time_cfg_handler:GET_NTP_CONFIG: enable_ntp: %d\n", msg.getNtpCfg().state);
                syslog(LOG_INFO, "time_cfg_handler:GET_NTP_CONFIG: ntp_server: %s\n", msg.getNtpCfg().ntp_server);
                break;
            }
            case app::rpcMessageTimeActionType::SET_NTP_CONFIG:
            {
                syslog(LOG_INFO, "time_cfg_handler:SET_NTP_CONFIG: enbale: %d\n", msg.getNtpCfg().state);
                syslog(LOG_INFO, "time_cfg_handler:SET_NTP_CONFIG: ntp_server: %s\n", msg.getNtpCfg().ntp_server);
                app::serviceNtp::getInstance()->setNtpCfg(msg.getNtpCfg());
                msg.setMsgResult(app::rpcMessageTimeResultType::SUCCESS);
                break;
            }
        }
    }

    return msg.serialize(socket_fd);
}

void timeManager_init(app::rpcUnixServer &rpcServer)
{
    rpcServer.registerMessageHandler(app::rpcMessage::rpcMessageType::handle_time_cfg, time_cfg_handler);
}

