/*
 * event_manager.cpp
 *
 *  Created on: Aug 28, 2018
 *      Author: nmhien
 */
#include "event_manager.h"
#include "rpcUnixServer.h"
#include "rpcMessageEvents.h"
#include "eventNotification.h"
#include "utilities.h"
#include "netlink_socket.h"

void event_manager_init()
{
    app::rpcMessageAddr addr = app::rpcMessageAddr::getRpcMessageAddrbyType(
            app::rpcMessageAddr::rpcMessageAddrType::event_manager_addr_t);

    if (app::rpcUnixServer::getInstance()->openServer(addr) != true) {
        syslog(LOG_ERR, "cannot open unix socket server");
        exit(EXIT_FAILURE);
    }
}

static bool get_event_handler(int socker_fd) {
    app::rpcMessageEvents msg;
    if (msg.deserialize(socker_fd)) {
        uint16_t events = app::eventNotification::getInstance()->getEvents();
        msg.setEvents(events);
        return msg.serialize(socker_fd);
    }
    return false;
}

static int recv_and_store_event(int sock)
{
    struct iovec iov;
    struct msghdr msg;
    int bytes;
    struct sockaddr_nl daddr;
    struct nlmsghdr *nlh;

    nlh = (struct nlmsghdr*) malloc(NLMSG_SPACE(MAX_EVENT_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_EVENT_PAYLOAD));

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *) nlh;
    iov.iov_len = NLMSG_SPACE(MAX_EVENT_PAYLOAD);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *) &daddr;
    msg.msg_namelen = sizeof(daddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    bytes = recvmsg(sock, &msg, 0);
    if (bytes <= 0) {
        syslog(LOG_ERR, "recvmsg()");
        free(nlh);
        return -1;
    }

    app::eventNotification::getInstance()->setEvents(*(uint16_t*) NLMSG_DATA(nlh));

    free(nlh);
    return bytes;
}

static int open_netlink_event()
{
    int                fd;
    struct sockaddr_nl sa;
    int                group = NETLINK_EVENTS_GROUP;

    if ((fd = open_netlink_socket(NETLINK_USERSOCK)) == -1) {
        syslog(LOG_ERR, "open_netlink_socket failed\n");
        goto error_exit;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = getpid();

    if (bind_netlink_socket(fd, &sa, sizeof(sa)) == -1) {
        syslog(LOG_ERR, "bind_netlink_socket failed\n");
        goto error_exit;
    }

    if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) == -1) {
        syslog(LOG_ERR, "setsockopt failed\n");
        goto error_exit;
    }

    return fd;

error_exit:
    if (fd != -1) {
        close(fd);
    }

    return 0;
}

void event_manager_service_loop()
{
    fd_set read_fds;
    int event_sock;
    app::rpcUnixServer *rpcServer = app::rpcUnixServer::getInstance();
    int server_socket = rpcServer->get_socket();
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::get_event_notification,
                                      get_event_handler);

    if ((event_sock = open_netlink_event()) == 0) {
        syslog(LOG_ERR, "cannot open netlink event\n");
        exit(EXIT_FAILURE);
    }

    std::list<int> listReadFd;
    listReadFd.push_back(event_sock);
    listReadFd.push_back(server_socket);

    while (1) {
        int maxfd = build_fd_sets(&read_fds, listReadFd);

        int activity = select(maxfd + 1, &read_fds, NULL, NULL, NULL);
        sleep(1);

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
                if (FD_ISSET(event_sock, &read_fds)) {
                    recv_and_store_event(event_sock);
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
