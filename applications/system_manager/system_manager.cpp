#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <syslog.h>
#include <error.h>

#include <iostream>
#include <list>

#include "utilities.h"
#include "serviceHiawatha.h"
#include "serviceNtp.h"
#include "serviceOpenvpn.h"
#include "userManager.h"
#include "simpleTimerSync.h"
#include "firmwareManager.h"
#include "rpcUnixServer.h"
#include "rpcMessageAddr.h"
#include "rpcMessageFirmware.h"
#include "rpcMessageUsers.h"

#define CONFIG_DIR "/tmp/configs"

void mount_sd_card() {

    if (access("/dev/mmcblk0p1", F_OK) == -1) {
        syslog(LOG_ERR, "/dev/mmcblk0p1 is not existed");
        return;
    }

    if (access("/boot", F_OK) == -1) {
        syslog(LOG_ERR, "/boot is not existed");
        return;
    }

    if (system("mount -t vfat /dev/mmcblk0p1 /boot") != 0) {
        syslog(LOG_ERR, "cannot mount /dev/mmcblk0p1 to /boot");
        return;
    }

    if (access("/dev/mmcblk0p2", F_OK) == -1) {
        syslog(LOG_ERR, "/dev/mmcblk0p2 is not existed");
        return;
    }

    if (access("/data", F_OK) == -1) {
        syslog(LOG_ERR, "/data is not existed");
        return;
    }

    if (system("mount -t ext4 /dev/mmcblk0p2 /data") != 0) {
        syslog(LOG_ERR, "cannot mount /dev/mmcblk0p2 to /data");
        return;
    }
}

void system_manager_init()
{
    mkdir(CONFIG_DIR, 0755);

    mount_sd_card();

    app::userManager::getInstance()->initFromFile();

    // start web server
    app::serviceHiawatha::getInstance()->init();
    app::serviceHiawatha::getInstance()->start();
    app::serviceNtp::getInstance()->init();
    app::serviceNtp::getInstance()->start();
    app::serviceOpenvpn::getInstance()->init();
    app::serviceOpenvpn::getInstance()->start();

    system("web_handler");

    app::rpcMessageAddr addr = app::rpcMessageAddr::getRpcMessageAddrbyType(
            app::rpcMessageAddr::rpcMessageAddrType::system_manager_addr_t);

    if (app::rpcUnixServer::getInstance()->openServer(addr) != true) {
        syslog(LOG_ERR, "cannot open unix socket server");
        exit(EXIT_FAILURE);
    }
}

static bool firmware_action_handler(int socket_fd)
{
    app::rpcMessageFirmware msgFirmware;
    if (msgFirmware.deserialize(socket_fd)) {

        app::rpcMessageFirmwareData_t msgData = msgFirmware.getFirmwareMsgData();

        switch (msgFirmware.getFirmwareMsgAction())
        {
            case app::rpcFirmwareActionType::GET_STATUS:
            {
                msgData.status = app::firmwareManager::getInstance()->getFirmwareStatus();
                msgData.result = app::firmwareManager::getInstance()->getFirmwareResult();

                msgFirmware.setFirmwareMsgData(msgData);
                break;
            }

            case app::rpcFirmwareActionType::DO_UPGRADE:
            {
                app::firmwareManager::getInstance()->setFirmwareName(msgFirmware.getFirmwareMsgData().fwName);
                app::firmwareManager::getInstance()->setFirmwareReboot(msgFirmware.getFirmwareMsgData().reboot);

                if (app::firmwareManager::getInstance()->doAsynUpgrade() == false) {
                    return false;
                }

                msgData.status = app::firmwareManager::getInstance()->getFirmwareStatus();
                msgData.result = app::firmwareManager::getInstance()->getFirmwareResult();
                msgFirmware.setFirmwareMsgData(msgData);
                break;
            }
            case app::rpcFirmwareActionType::GET_INFO:
            {
                msgData.fwDate = app::firmwareManager::getInstance()->getFirmwareDate();
                msgData.fwDesc = app::firmwareManager::getInstance()->getFirmwareDesc();
                msgFirmware.setFirmwareMsgData(msgData);

                break;
            }

            default:
                break;
        }

        return msgFirmware.serialize(socket_fd);
    }

    return false;
}

static bool users_action_handler(int socket_fd)
{
    app::rpcMessageUsers msgUsers;

    if (msgUsers.deserialize(socket_fd)) {
        switch (msgUsers.getMsgAction())
        {
            case app::rpcMessageUsersActionType::GET_USERS:
            {
                msgUsers.setUsers(app::userManager::getInstance()->getUsers());
                return msgUsers.serialize(socket_fd);
            }

            case app::rpcMessageUsersActionType::ADD_USER:
            {
                msgUsers.setMsgResult(app::userManager::getInstance()->addUser(msgUsers.getUser()));

                return msgUsers.serialize(socket_fd);
            }

            case app::rpcMessageUsersActionType::EDIT_USER:
            {
                msgUsers.setMsgResult(app::userManager::getInstance()->editUser(msgUsers.getUser(),
                                                                                msgUsers.getEditPwd()));

                return msgUsers.serialize(socket_fd);
            }

            default:
                break;
        }
    }

    return false;
}

void system_manager_service_loop()
{
    fd_set read_fds;
    app::rpcUnixServer *rpcServer = app::rpcUnixServer::getInstance();
    int server_socket = rpcServer->get_socket();
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::handle_firmware_action, firmware_action_handler);
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::handle_users_action, users_action_handler);

    std::list<int> listReadFd;
    listReadFd.push_back(server_socket);

    while(1) {
        int maxfd = build_fd_sets(&read_fds, listReadFd);

        int activity = select(maxfd + 1, &read_fds, NULL, NULL, NULL);

        switch (activity) {
             case -1:
                 if(errno != EINTR) {
                     exit(EXIT_FAILURE);
                 }
                 break;
             case 0:
               // TODO
               continue;

             default:
             {
                 if (FD_ISSET(server_socket, &read_fds)) {
                     if (rpcServer->doReply() == false) {
                        syslog(LOG_ERR, "fail to handle new connection");
                     }
                 }

             }
        }
    }
}
