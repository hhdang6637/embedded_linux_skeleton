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

static bool setSystemTime(const struct tm &time)
{
    // TODO set system time

    return true;
}

static struct tm getSystemTime()
{
    struct tm time;
    // TODO get system time

    return time;
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
                break;
            }
            case app::rpcMessageTimeActionType::SET_SYSTEM_TIME:
            {
                setSystemTime(msg.getSystemTime());
                break;
            }
            case app::rpcMessageTimeActionType::GET_NTP_CONFIG:
            {
                msg.setNtpCfg(app::serviceNtp::getInstance()->getNtpCfg());
                break;
            }
            case app::rpcMessageTimeActionType::SET_NTP_CONFIG:
            {
                app::serviceNtp::getInstance()->setNtpCfg(msg.getNtpCfg());
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

