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
int open_nl_socket()
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        syslog(LOG_ERR, "Create socket error: %s\n", strerror(errno));
        return -1;
    }

    return fd;
}

// bind netlink socket to kernerl space
int bind_nl_socket(int fd, struct sockaddr_nl *sa, int size)
{
    if (bind(fd, (struct sockaddr *) sa, size) < 0) {
        syslog(LOG_ERR, "Bind socket error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int send_nl_get_request(int fd, int ifi_index, const struct sockaddr_nl *sa, int size, int seq)
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
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_type = ARPHRD_NETROM;
    req.ifi.ifi_index = ifi_index;

    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *) sa, size) < 0) {
        syslog(LOG_ERR, "Send pkg error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int recv_nl_response(int fd, char *buffer, int size)
{
    int nbytes;
    if ((nbytes = recv(fd, buffer, size, 0)) < 0) {
        syslog(LOG_ERR, "Recv pkg error: %s\n", strerror(errno));
        return -1;
    }

    return nbytes;
}

void parse_nl_data(char *buffer, int len, struct net_device_stats *stats)
{
    struct nlmsghdr  *nl_header;
    struct ifinfomsg *if_info;
    struct rtattr    *attr;
    int              attr_len;

    nl_header = (struct nlmsghdr *) buffer;

    /* Check if there is still any pkg waiting */
    while (NLMSG_OK(nl_header, len)) {
        /* Got the complete response now */
        if (nl_header->nlmsg_type == NLMSG_DONE) {
            /* Ending pkg - no need to handle */
            break;
        }

        /* Check for error */
        if (nl_header->nlmsg_type == NLMSG_ERROR) {
            /* This is a netlink error msg */
#ifdef DEBUG_NETLINK
            struct nlmsgerr *pstruError;
            pstruError = (struct nlmsgerr *) NLMSG_DATA(nl_header);
            NL_DEBUG_PRINT(stderr, "netlink msg error: %s\n", strerror(pstruError->error));
#endif
            break;
        }

        /* Handle the response from the kernel */
        if_info = (ifinfomsg *) NLMSG_DATA(nl_header);
        NL_DEBUG_PRINT(stderr, "Got device[%d] info\n", if_info->ifi_index);
        /* Get the device type */
        NL_DEBUG_PRINT(stderr, "\tdevice type: ");
        switch (if_info->ifi_type)
        {
            case ARPHRD_ETHER:
                NL_DEBUG_PRINT(stderr, "Ethernet\n");
                break;
            case ARPHRD_PPP:
                NL_DEBUG_PRINT(stderr, "PPP\n");
                break;
            case ARPHRD_LOOPBACK:
                NL_DEBUG_PRINT(stderr, "Loopback\n");
                break;
            default:
                NL_DEBUG_PRINT(stderr, "Unknown\n");
                break;
        }
        /* Get the device status */
        NL_DEBUG_PRINT(stderr, "\tdevice status:");
        if ((if_info->ifi_flags & IFF_UP) == IFF_UP) {
            NL_DEBUG_PRINT(stderr, " UP");
        }
        if ((if_info->ifi_flags & IFF_BROADCAST) == IFF_BROADCAST) {
            NL_DEBUG_PRINT(stderr, " BROADCAST");
        }
        if ((if_info->ifi_flags & IFF_DEBUG) == IFF_DEBUG) {
            NL_DEBUG_PRINT(stderr, " DEBUG");
        }
        if ((if_info->ifi_flags & IFF_LOOPBACK) == IFF_LOOPBACK) {
            NL_DEBUG_PRINT(stderr, " LOOPBACK");
        }
        if ((if_info->ifi_flags & IFF_POINTOPOINT) == IFF_POINTOPOINT) {
            NL_DEBUG_PRINT(stderr, " POINTOPOINT");
        }
        if ((if_info->ifi_flags & IFF_RUNNING) == IFF_RUNNING) {
            NL_DEBUG_PRINT(stderr, " RUNNING");
        }
        if ((if_info->ifi_flags & IFF_NOARP) == IFF_NOARP) {
            NL_DEBUG_PRINT(stderr, " NOARP");
        }
        if ((if_info->ifi_flags & IFF_PROMISC) == IFF_PROMISC) {
            NL_DEBUG_PRINT(stderr, " PROMISC");
        }
        if ((if_info->ifi_flags & IFF_NOTRAILERS) == IFF_NOTRAILERS) {
            NL_DEBUG_PRINT(stderr, " NOTAILERS");
        }
        if ((if_info->ifi_flags & IFF_ALLMULTI) == IFF_ALLMULTI) {
            NL_DEBUG_PRINT(stderr, " ALLMULTI");
        }
        if ((if_info->ifi_flags & IFF_MASTER) == IFF_MASTER) {
            NL_DEBUG_PRINT(stderr, " MASTER");
        }
        if ((if_info->ifi_flags & IFF_SLAVE) == IFF_SLAVE) {
            NL_DEBUG_PRINT(stderr, " SLAVE");
        }
        if ((if_info->ifi_flags & IFF_MULTICAST) == IFF_MULTICAST) {
            NL_DEBUG_PRINT(stderr, " MULTICAST");
        }
        if ((if_info->ifi_flags & IFF_PORTSEL) == IFF_PORTSEL) {
            NL_DEBUG_PRINT(stderr, " PORTSEL");
        }
        if ((if_info->ifi_flags & IFF_AUTOMEDIA) == IFF_AUTOMEDIA) {
            NL_DEBUG_PRINT(stderr, " AUTOMEDIA");
        }
        if ((if_info->ifi_flags & IFF_DYNAMIC) == IFF_DYNAMIC) {
            NL_DEBUG_PRINT(stderr, " DYNAMIC");
        }
        NL_DEBUG_PRINT(stderr, "\n");

        /* Retrieve the attributes */
        attr = IFLA_RTA(if_info);
        attr_len = NLMSG_PAYLOAD(nl_header, sizeof(struct ifinfomsg));
        while (RTA_OK(attr, attr_len)) {
            /* Check the type of this valid attribute */
            switch (attr->rta_type)
            {
                case IFLA_IFNAME:
                    NL_DEBUG_PRINT(stderr, "\tdevice name: %s\n", (char *)RTA_DATA(attr));
                    break;
                case IFLA_MTU:
                    NL_DEBUG_PRINT(stderr, "\tdevice MTU: %d\n", *(unsigned int *)RTA_DATA(attr));
                    break;
                case IFLA_QDISC:
                    NL_DEBUG_PRINT(stderr, "\tdevice Queueing discipline: %s\n", (char *)RTA_DATA(attr));
                    break;
                case IFLA_ADDRESS:
                {
#ifdef DEBUG_NETLINNK
                    struct ether_addr *ether;
                    if (if_info->ifi_type == ARPHRD_ETHER) {
                        ether = (struct ether_addr *) RTA_DATA(attr);
                        NL_DEBUG_PRINT(stderr, "\tMAC address: %s\n", ether_ntoa(ether));
                    }
#endif
                    break;
                }
                case IFLA_BROADCAST:
                {
#ifdef DEBUG_NETLINK
                    struct ether_addr *ether;
                    if (if_info->ifi_type == ARPHRD_ETHER) {
                        ether = (struct ether_addr *) RTA_DATA(attr);
                        NL_DEBUG_PRINT(stderr, "\tBROADCAST address: %s\n", ether_ntoa(ether));
                    }
#endif
                    break;
                }
                case IFLA_STATS:
                    struct net_device_stats *temp_stats;
                    temp_stats = (struct net_device_stats *) RTA_DATA(attr);
                    memcpy(stats, temp_stats, sizeof(struct net_device_stats));

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
                    break;
                default:
                    break;
            }

            /* Get the next attribute */
            attr = RTA_NEXT(attr, attr_len);
        }

        /* Get the next netlink msg */
        nl_header = NLMSG_NEXT(nl_header, len);
    }
}

/**
 *  get network statistics of interface index
 */
int get_network_stats(int ifi_index, struct net_device_stats *stats)
{
    int fd;
    struct sockaddr_nl sa;
    char buffer[BUF_SIZE];
    int nbytes;
    int seq_number = 0;

    if ((fd = open_nl_socket()) == -1) {
        syslog(LOG_ERR, "open_nl_socket failed\n");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    if (bind_nl_socket(fd, &sa, sizeof(sa)) == -1) {
        syslog(LOG_ERR, "bind_nl_socket failed\n");
        return -1;
    }

    if (send_nl_get_request(fd, ifi_index, &sa, sizeof(sa), ++seq_number) == -1) {
        syslog(LOG_ERR, "send_nl_get_request failed\n");
        return -1;
    }

    if ((nbytes = recv_nl_response(fd, buffer, sizeof(buffer))) == -1) {
        syslog(LOG_ERR, "recv_nl_response failed\n");
        return -1;
    }

    parse_nl_data(buffer, nbytes, stats);

    return 0;
}

