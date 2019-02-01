#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>

#include "utilities.h"
#include "serviceDhcpC.h"
#include "rpcUnixServer.h"
#include "rpcMessageAddr.h"

#if defined (pi_3_b) || defined (orange_pi_zero)
#include "serviceHostapd.h"
#include "serviceDnsmasq.h"
#include "rpcMessageWifiSetting.h"
#endif

#if defined (pi_3_b) || defined (orange_pi_zero)
app::serviceHostapd* serviceHostapd;
#endif

static bool _network_manager_wake_up(const char* interfaceName)
{
    struct ifreq ifr;
    int socket_fd;
    bool rc = true;

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (socket_fd == -1) {
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));

    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", interfaceName);
    ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;

    if (ioctl(socket_fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("cannot wake up interaface");
        rc = false;
        goto exit;
    }

    exit: close(socket_fd);
    return rc;
}

void network_manager_init()
{

    // TODO

    sleep(5);

    // start network interface eth0
    if (_network_manager_wake_up("eth0")) {
        // start udhcp
        app::serviceDhcpC::getInstance()->init();
#if defined (orange_pi_zero)
        // hack, we're using orange_pi_zero as vpn server with bridge mode.
        system("/bin/busybox brctl addbr br0");
        system("/bin/busybox brctl addif br0 eth0");
        _network_manager_wake_up("br0");
        app::serviceDhcpC::getInstance()->addManagedInterfaces("br0");
#else
        app::serviceDhcpC::getInstance()->addManagedInterfaces("eth0");
#endif
        app::serviceDhcpC::getInstance()->start();
    }

#if defined (pi_3_b) || defined (orange_pi_zero)

    if (_network_manager_wake_up("wlan0")) {
        // start hostapd
        serviceHostapd = app::serviceHostapd::getInstance();
        serviceHostapd->init();
        serviceHostapd->start();
        app::serviceDnsmasq::getInstance()->init();
        app::serviceDnsmasq::getInstance()->start();
        system("ifconfig wlan0 10.0.0.1 netmask 255.255.255.0");
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        // FIXME - hardcode ip and interface
        setenv("XTABLES_LIBDIR", "/usr/lib", 1);
#if defined (orange_pi_zero)
        system("iptables -t nat -I POSTROUTING -o br0 -s 10.0.0.0/24 -j MASQUERADE");
#else
        system("iptables -t nat -I POSTROUTING -o eth0 -s 10.0.0.0/24 -j MASQUERADE");
#endif
    }
    if (access("/data/no-ip2.conf", F_OK) != -1) {
        system("noip2 -c /data/no-ip2.conf");
    }
#endif

    app::rpcMessageAddr addr = app::rpcMessageAddr::getRpcMessageAddrbyType(
            app::rpcMessageAddr::rpcMessageAddrType::network_manager_addr_t);

    if (app::rpcUnixServer::getInstance()->openServer(addr) != true) {
        syslog(LOG_ERR, "cannot open unix socket server");
        exit(EXIT_FAILURE);
    }
}

#if defined (pi_3_b) || defined (orange_pi_zero)
static bool wifi_setting_action_handler(int socket_fd)
{
    app::rpcMessageWifiSetting msgWifiSetting;

    if (msgWifiSetting.deserialize(socket_fd)) {
        switch (msgWifiSetting.getMsgAction())
        {
            case app::rpcMessageWifiSettingActionType::GET_WIFI_SETTING:
            {
                msgWifiSetting.setMsgResult(app::rpcMessageWifiSettingResultType::UNKNOWN_ERROR);
                if (serviceHostapd != 0) {
                    msgWifiSetting.setWifiSettingMsgData(serviceHostapd->getWifiSettingData());
                    msgWifiSetting.setMsgResult(app::rpcMessageWifiSettingResultType::SUCCEEDED);
                }
                break;
            }

            case app::rpcMessageWifiSettingActionType::EDIT_WIFI_SETTING:
            {
                auto result = app::rpcMessageWifiSettingResultType::UNKNOWN_ERROR;
                if (serviceHostapd != 0) {
                    auto msgData = msgWifiSetting.getWifiSettingMsgData();
                    result = serviceHostapd->validateMsgConfig(&msgData);

                    if (result == app::rpcMessageWifiSettingResultType::SUCCEEDED) {
                        serviceHostapd->setWifiSettingData(msgData);
                        if (serviceHostapd->restart() == false) {
                            result = app::rpcMessageWifiSettingResultType::UNKNOWN_ERROR;
                        }
                    }
                }

                msgWifiSetting.setMsgResult(result);
                break;
            }
        }

        return msgWifiSetting.serialize(socket_fd);
    }
    return false;
}
#endif

void network_manager_service_loop()
{
    fd_set read_fds;
    int server_socket;

    app::rpcUnixServer *rpcServer = app::rpcUnixServer::getInstance();
    server_socket = rpcServer->get_socket();
#if defined (pi_3_b) || defined (orange_pi_zero)
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::handle_wifi_setting, wifi_setting_action_handler);
#endif
    std::list<int> listReadFd;
    listReadFd.push_back(rpcServer->get_socket());

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
