/*
 * resource_manager.cpp
 *
 *  Created on: Aug 14, 2018
 *      Author: nmhien
 */

#include "resource_manager.h"
#include "rpcUnixServer.h"
#include "rpcUnixClient.h"
#include "rpcMessageResourceHistory.h"
#include "rpcMessageFirmware.h"
#include "simpleTimerSync.h"
#include "resourceCollector.h"
#include "utilities.h"

void resource_manager_init()
{
    app::rpcMessageAddr addr = app::rpcMessageAddr::getRpcMessageAddrbyType(
            app::rpcMessageAddr::rpcMessageAddrType::resource_manager_addr_t);

    if (app::rpcUnixServer::getInstance()->openServer(addr) != true) {
        syslog(LOG_ERR, "cannot open unix socket server");
        exit(EXIT_FAILURE);
    }
}

static bool get_resource_history_handler(int socker_fd) {
    app::rpcMessageResourceHistory msgResourceHistory;
    if (msgResourceHistory.deserialize(socker_fd)) {
        switch (msgResourceHistory.getMsgAction())
        {
            case app::rpcResourceActionType::GET_RESOURCE_HISTORY:
            {
                std::list<cpu_stat_t> cpu_history = app::resourceCollector::getInstance()->get_cpu_history();
                std::list<struct sysinfo> ram_history = app::resourceCollector::getInstance()->get_ram_history();
                std::string interface_name = msgResourceHistory.get_interface_name();
                std::list<struct rtnl_link_stats> network_history = app::resourceCollector::getInstance()
                        ->get_network_history(interface_name);

                msgResourceHistory.set_cpu_history(cpu_history);
                msgResourceHistory.set_ram_history(ram_history);
                msgResourceHistory.set_network_history(network_history);
                msgResourceHistory.set_max_tx(app::resourceCollector::getInstance()
                        ->get_max_tx(interface_name));
                msgResourceHistory.set_max_rx(app::resourceCollector::getInstance()
                        ->get_max_rx(interface_name));

                break;
            }
            case app::rpcResourceActionType::GET_GENERAL_INFO:
            {
                app::resourceGeneralInfo_t info;
                info.current_cpu = app::resourceCollector::getInstance()->get_current_cpu();
                info.current_ram = app::resourceCollector::getInstance()->get_current_ram();
                info.temperature = app::resourceCollector::getInstance()->get_temperature();

                {
                    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
                    app::rpcMessageFirmware msg;

                    msg.setFirmwareMsgAction(app::rpcFirmwareActionType::GET_INFO);

                    if (rpcClient->doRpc(&msg) == false) {
                        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
                        return false;
                    }

                    strncpy(info.fw_description, msg.getFirmwareMsgData().fwDesc.c_str(), sizeof(info.fw_description));
                    info.fw_description[sizeof(info.fw_description) -1] = '\0';
                }

                info.current_time = time(NULL);;
                msgResourceHistory.set_general_info(info);

                break;
            }
        }

        return msgResourceHistory.serialize(socker_fd);
    }
    return false;
}

static void resourceHistoryCollect() {
    app::resourceCollector::getInstance()->cpu_do_collect();
    app::resourceCollector::getInstance()->ram_do_collect();
    app::resourceCollector::getInstance()->network_do_collect();
#if (defined pi_b_plus) || (defined pi_3_b)
    app::resourceCollector::getInstance()->temperature_collect();
#endif
}

void resource_manager_service_loop()
{
    fd_set read_fds;
    app::rpcUnixServer *rpcServer = app::rpcUnixServer::getInstance();
    int server_socket = rpcServer->get_socket();
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::get_resource_history,
                                      get_resource_history_handler);

    app::simpleTimerSync *timer = app::simpleTimerSync::getInstance();
    timer->init(1000);
    timer->addCallback(1000, resourceHistoryCollect);
    timer->start();

    std::list<int> listReadFd;
    listReadFd.push_back(timer->getTimterFd());
    listReadFd.push_back(server_socket);

    while (1) {
        int maxfd = build_fd_sets(&read_fds, listReadFd);

        int activity = select(maxfd + 1, &read_fds, NULL, NULL, NULL);

        switch (activity)
        {
            case -1:
                if (errno != EINTR) {
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
