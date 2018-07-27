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
#include "rpcUnixServer.h"
#include "rpcMessageAddr.h"

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
        system("udhcpc eth0");
    }

    app::rpcMessageAddr addr = app::rpcMessageAddr::getRpcMessageAddrbyType(
            app::rpcMessageAddr::rpcMessageAddrType::network_manager_addr_t);

    if (app::rpcUnixServer::getInstance()->openServer(addr) != true) {
        syslog(LOG_ERR, "cannot open unix socket server");
        exit(EXIT_FAILURE);
    }
}

void network_manager_service_loop()
{
    fd_set read_fds;
    int server_socket;

    app::rpcUnixServer *rpcServer = app::rpcUnixServer::getInstance();
    server_socket = rpcServer->get_socket();

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
