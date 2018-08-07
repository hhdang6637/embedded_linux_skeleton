/*
 * netlink_socket.c
 *
 *  Created on: Aug 6, 2018
 *      Author: nmhien
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <net/if_arp.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <syslog.h>

#include "netlink_socket.h"

//#define DEBUG_NETLINK 1
#ifdef DEBUG_NETLINK
#define NL_DEBUG_PRINT(fd, msg, args... ) do { \
         fprintf(fd, msg, ##args); \
         } while (0)
#else
#define NL_DEBUG_PRINT( msg, args... ) do { } while (0)
#endif

#define BUF_SIZE 4096

/* Create the netlink socket with netlink_route */
int open_netlink_socket()
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        syslog(LOG_ERR, "Create socket error: %s\n", strerror(errno));
        return -1;
    }

    return fd;
}

// bind netlink socket to kernerl space
int bind_netlink_socket(int fd, struct sockaddr_nl *sa, int size)
{
    if (bind(fd, (struct sockaddr *) sa, size) < 0) {
        syslog(LOG_ERR, "Bind socket error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int send_netlink_get_request(int fd, int ifi_index, const struct sockaddr_nl *sa, int size, int seq)
{
    struct
    {
        struct nlmsghdr nh;
        struct ifinfomsg ifi;
    } req;

    /* Construct the request sending to the kernel */
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req));
    req.nh.nlmsg_type = RTM_GETLINK;
    req.nh.nlmsg_seq = seq;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_type = ARPHRD_NETROM;
    req.ifi.ifi_index = ifi_index;

    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *) sa, size) < 0) {
        syslog(LOG_ERR, "Send msg error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int recv_netlink_response(int fd, char *buffer, int size)
{
    int nbytes;
    if ((nbytes = recv(fd, buffer, size, 0)) < 0) {
        syslog(LOG_ERR, "Recv msg error: %s\n", strerror(errno));
        return -1;
    }

    return nbytes;
}

/*
 * Parse netlink data to net_device_stats structure
 * return TRUE if net_device_stats structure parsed succeed, or FALSE if an error occurred
 */
bool parse_netlink_data(char *buffer, int len, std::list<struct interface_info> &info)
{
    struct nlmsghdr       *nl_header;
    struct ifinfomsg      *if_info;
    struct rtattr         *attr;
    int                   attr_len;
    bool                  rc = false;
    struct interface_info tmp_info;

    nl_header = (struct nlmsghdr *) buffer;

    while (NLMSG_OK(nl_header, len)) {
        /* Got the complete response now */
        if (nl_header->nlmsg_type == NLMSG_DONE) {
            /* Ending of msg - no need to handle */
            break;
        }

        /* Check for error */
        if (nl_header->nlmsg_type == NLMSG_ERROR) {
            /* This is a netlink error msg */
            struct nlmsgerr *error = (struct nlmsgerr *) NLMSG_DATA(nl_header);
            if (error->error != 0) {
                syslog(LOG_ERR, "netlink msg error: %s\n", strerror(error->error));
                rc = false;
                goto out;
            }
            break;
        }

        /* Handle the response from the kernel */
        if_info = (ifinfomsg *) NLMSG_DATA(nl_header);

        NL_DEBUG_PRINT(stderr, "Got device[%d] info\n", if_info->ifi_index);

        /* Retrieve the attributes */
        attr = IFLA_RTA(if_info);
        attr_len = NLMSG_PAYLOAD(nl_header, sizeof(struct ifinfomsg));
        while (RTA_OK(attr, attr_len)) {
            /* Check the type of this valid attribute */
            switch (attr->rta_type)
            {
                case IFLA_IFNAME: {
                    char *if_name = (char *)RTA_DATA(attr);
                    NL_DEBUG_PRINT(stderr, "\tdevice name: %s\n",if_name);
                    strncpy(tmp_info.if_name, if_name, MAX_IFNAME_LEN);
                    tmp_info.if_name[MAX_IFNAME_LEN] = '\0';
                    break;
                }
                case IFLA_STATS: {
                    struct net_device_stats *temp_stats;
                    temp_stats = (struct net_device_stats *) RTA_DATA(attr);
                    memcpy(&tmp_info.if_stats, temp_stats, sizeof(struct net_device_stats));

                    NL_DEBUG_PRINT(stderr, "\treceive info:\n");
                    NL_DEBUG_PRINT(stderr, "\t\treceive packets: %lu, bytes: %lu\n", temp_stats->rx_packets,
                                   temp_stats->rx_bytes);
                    NL_DEBUG_PRINT(stderr, "\t\terrors: %lu, dropped: %lu, multicast: %lu, collisions: %lu\n",
                                   temp_stats->rx_errors, temp_stats->rx_dropped, temp_stats->multicast,
                                   temp_stats->collisions);
                    NL_DEBUG_PRINT(stderr, "\t\tlength: %lu, over: %lu, crc: %lu, frame: %lu, fifo: %lu, missed: %lu\n",
                                   temp_stats->rx_length_errors, temp_stats->rx_over_errors, temp_stats->rx_crc_errors,
                                   temp_stats->rx_frame_errors, temp_stats->rx_fifo_errors,
                                   temp_stats->rx_missed_errors);
                    NL_DEBUG_PRINT(stderr, "\tsend info:\n");
                    NL_DEBUG_PRINT(stderr, "\t\tsend packets: %lu, bytes: %lu\n", temp_stats->tx_packets,
                                   temp_stats->tx_bytes);
                    NL_DEBUG_PRINT(stderr, "\t\terrors: %lu, dropped: %lu\n", temp_stats->tx_errors,
                                   temp_stats->tx_dropped);
                    NL_DEBUG_PRINT(stderr, "\t\taborted: %lu, carrier: %lu, fifo: %lu, heartbeat: %lu, window: %lu\n",
                                   temp_stats->tx_aborted_errors, temp_stats->tx_carrier_errors,
                                   temp_stats->tx_fifo_errors, temp_stats->tx_heartbeat_errors,
                                   temp_stats->tx_window_errors);
                    rc = true;
                    break;
                }
                default:
                    break;
            }

            /* Get the next attribute */
            attr = RTA_NEXT(attr, attr_len);
        }

        /* Get the next netlink msg */
        nl_header = NLMSG_NEXT(nl_header, len);

        info.push_back(tmp_info);
    }

out:
    return rc;
}

/**
 *  get network statistics of all interface from kernel (pid: 0)
 */
bool get_network_stats(std::list<struct interface_info> &info)
{
    int fd;
    struct sockaddr_nl sa;
    char buffer[BUF_SIZE];
    int nbytes;
    static int seq_number = 0;

    if ((fd = open_netlink_socket()) == -1) {
        syslog(LOG_ERR, "open_nl_socket failed\n");
        goto error_exit;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    if (bind_netlink_socket(fd, &sa, sizeof(sa)) == -1) {
        syslog(LOG_ERR, "bind_nl_socket failed\n");
        goto error_exit;
    }

    if (send_netlink_get_request(fd, 0, &sa, sizeof(sa), ++seq_number) == -1) {
        syslog(LOG_ERR, "send_nl_get_request failed\n");
        goto error_exit;
    }

    if ((nbytes = recv_netlink_response(fd, buffer, sizeof(buffer))) == -1) {
        syslog(LOG_ERR, "recv_nl_response failed\n");
        goto error_exit;
    }

    if (parse_netlink_data(buffer, nbytes, info))
    {
        return true;
    }

error_exit:

    if (fd != -1) {
        close(fd);
    }

    return false;
}

