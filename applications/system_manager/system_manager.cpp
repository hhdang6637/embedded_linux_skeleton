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
#include "simpleTimerSync.h"
#include "resourceCollector.h"
#include "firmwareManager.h"
#include "rpcUnixServer.h"
#include "rpcMessageAddr.h"
#include "rpcMessageResourceHistory.h"
#include "rpcMessageFirmware.h"

#define CONFIG_DIR "/tmp/configs"

void system_manager_init()
{

    mkdir(CONFIG_DIR, 0755);
    // start web server
    app::serviceHiawatha::getInstance()->init();
    app::serviceHiawatha::getInstance()->start();

    system("web_handler");

#ifdef arm_vexpress_a9
    if ((access("/dev/mmcblk0", F_OK)) != -1 && (access("/boot", F_OK) != -1)) {
        system("mount -t vfat /dev/mmcblk0 /boot");
    }
#else
    if ((access("/dev/mmcblk0p1", F_OK)) != -1 && (access("/boot", F_OK) != -1)) {
        system("mount -t vfat /dev/mmcblk0p1 /boot");
    }

    if ((access("/dev/mmcblk0p2", F_OK)) != -1 && (access("/data", F_OK) != -1)) {
        system("mount -t ext4 /dev/mmcblk0p2 /data/");
    }
#endif

    app::rpcMessageAddr addr = app::rpcMessageAddr::getRpcMessageAddrbyType(
            app::rpcMessageAddr::rpcMessageAddrType::system_manager_addr_t);

    if (app::rpcUnixServer::getInstance()->openServer(addr) != true) {
        syslog(LOG_ERR, "cannot open unix socket server");
        exit(EXIT_FAILURE);
    }
}

static void resourceHistoryCollect() {
    app::resourceCollector::getInstance()->cpu_do_collect();
    app::resourceCollector::getInstance()->ram_do_collect();
    app::resourceCollector::getInstance()->network_do_collect();
}

static bool get_resource_history_handler(int socker_fd) {
    app::rpcMessageResourceHistory msgResourceHistory;
    if (msgResourceHistory.deserialize(socker_fd)) {
        std::list<cpu_stat_t> cpu_history     = app::resourceCollector::getInstance()->get_cpu_history();
        std::list<struct sysinfo> ram_history = app::resourceCollector::getInstance()->get_ram_history();
        std::string interface_name            = msgResourceHistory.get_interface_name();
        std::list<struct rtnl_link_stats> network_history = app::resourceCollector::getInstance()->get_network_history(interface_name);

        msgResourceHistory.set_cpu_history(cpu_history);
        msgResourceHistory.set_ram_history(ram_history);
        msgResourceHistory.set_network_history(network_history);
        return msgResourceHistory.serialize(socker_fd);
    }
    return false;
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

void system_manager_service_loop()
{
    fd_set read_fds;
    app::rpcUnixServer *rpcServer = app::rpcUnixServer::getInstance();
    int server_socket = rpcServer->get_socket();
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::get_resource_history, get_resource_history_handler);
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::handle_firmware_action, firmware_action_handler);

    app::simpleTimerSync *timer = app::simpleTimerSync::getInstance();
    timer->init(1000);
    timer->addCallback(1000, resourceHistoryCollect);
    timer->start();

    std::list<int> listReadFd;
    listReadFd.push_back(timer->getTimterFd());
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
                 if (FD_ISSET(timer->getTimterFd(), &read_fds)) {
                     timer->do_schedule();
                 }

                 if (FD_ISSET(server_socket, &read_fds)) {
                     if (rpcServer->doReply() == false) {
                        syslog(LOG_ERR, "fail to handle new connection");
                     }
                 }

             }
        }
    }
}
