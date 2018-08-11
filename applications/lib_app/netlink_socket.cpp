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
#include <linux/netdevice.h>
#include <net/if_arp.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <string>

#include "netlink_socket.h"

//#define DEBUG_NETLINK 1
#ifdef DEBUG_NETLINK
#define NL_DEBUG_PRINT(fd, msg, args... ) do { \
         fprintf(fd, msg, ##args); \
         } while (0)
#else
#define NL_DEBUG_PRINT( msg, args... ) do { } while (0)
#endif

#define BUF_SIZE 1024*6

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
int bind_netlink_socket(int fd, struct sockaddr_nl *sa, int sa_size)
{
    if (bind(fd, (struct sockaddr *) sa, sa_size) < 0) {
        syslog(LOG_ERR, "Bind socket error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * send the netlink get request to kernel
 */
int send_netlink_request(int fd, int pid, uint16_t nlmsg_type, uint16_t nlmsg_flags)
{
    struct nlmsghdr    nh;
    struct iovec       iov;
    struct sockaddr_nl sa;
    struct msghdr      msg;
    static int         seq_number = 0;

    /* Construct the request sending to the kernel */
    memset(&nh, 0, sizeof(nh));
    nh.nlmsg_len   = NLMSG_LENGTH(sizeof(nh));
    nh.nlmsg_type  = nlmsg_type;
    nh.nlmsg_seq   = seq_number;
    nh.nlmsg_flags = nlmsg_flags;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = 0;
    sa.nl_groups = 0;

    iov = {(void*)&nh, nh.nlmsg_len};
    msg = {&sa, sizeof(sa), &iov, 1, NULL, 0, 0};

    if (sendmsg(fd, &msg, 0) < 0) {
        syslog(LOG_ERR, "Send msg error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int recv_netlink_response(int fd, char *buffer, size_t buf_size)
{
    struct iovec       iov = { buffer, buf_size };
    struct sockaddr_nl sa;
    struct msghdr      msg;
    int                nbytes;

    msg = {&sa, sizeof(sa), &iov, 1, NULL, 0, 0};

    if ((nbytes = recvmsg(fd, &msg, 0)) < 0) {
        syslog(LOG_ERR, "Recv msg error: %s\n", strerror(errno));
        return -1;
    }

    return nbytes;
}

std::string device_type_to_str(struct ifinfomsg *if_info)
{
    std::string type;

    switch (if_info->ifi_type)
    {
        case ARPHRD_ETHER:
            type = "Ethernet";
            break;
        case ARPHRD_PPP:
            type = "PPP";
            break;
        case ARPHRD_LOOPBACK:
            type = "Loopback";
            break;
        default:
            type = "Unknown";
            break;
    }

    return type;
}

std::string link_status_to_str(struct ifinfomsg *if_info)
{
    std::string status;

    if ((if_info->ifi_flags & IFF_UP) == IFF_UP) {
        status += " UP";
    }
    if ((if_info->ifi_flags & IFF_BROADCAST) == IFF_BROADCAST) {
        status += " BROADCAST";
    }
    if ((if_info->ifi_flags & IFF_DEBUG) == IFF_DEBUG) {
        status += " DEBUG";
    }
    if ((if_info->ifi_flags & IFF_LOOPBACK) == IFF_LOOPBACK) {
        status += " LOOPBACK";
    }
    if ((if_info->ifi_flags & IFF_POINTOPOINT) == IFF_POINTOPOINT) {
        status += " POINTOPOINT";
    }
    if ((if_info->ifi_flags & IFF_RUNNING) == IFF_RUNNING) {
        status += " RUNNING";
    }
    if ((if_info->ifi_flags & IFF_NOARP) == IFF_NOARP) {
        status += " NOARP";
    }
    if ((if_info->ifi_flags & IFF_PROMISC) == IFF_PROMISC) {
        status += " PROMISC";
    }
    if ((if_info->ifi_flags & IFF_NOTRAILERS) == IFF_NOTRAILERS) {
        status += " NOTAILERS";
    }
    if ((if_info->ifi_flags & IFF_ALLMULTI) == IFF_ALLMULTI) {
        status += " ALLMULTI";
    }
    if ((if_info->ifi_flags & IFF_MASTER) == IFF_MASTER) {
        status += " MASTER";
    }
    if ((if_info->ifi_flags & IFF_SLAVE) == IFF_SLAVE) {
        status += " SLAVE";
    }
    if ((if_info->ifi_flags & IFF_MULTICAST) == IFF_MULTICAST) {
        status += " MULTICAST";
    }
    if ((if_info->ifi_flags & IFF_PORTSEL) == IFF_PORTSEL) {
        status += " PORTSEL";
    }
    if ((if_info->ifi_flags & IFF_AUTOMEDIA) == IFF_AUTOMEDIA) {
        status += " AUTOMEDIA";
    }
    if ((if_info->ifi_flags & IFF_DYNAMIC) == IFF_DYNAMIC) {
        status += " DYNAMIC";
    }

    return status;
}

/*
 * Parse netlink interface statistics
 * return TRUE if parsed succeed, or FALSE if an error occurred
 */
bool parse_netlink_interface_stats(char *buffer, int len, std::list<struct net_interface_stats> &stats)
{
    struct nlmsghdr            *nl_header;
    struct ifinfomsg           *if_info;
    struct rtattr              *attr;
    int                        attr_len;
    bool                       rc = true;
    struct net_interface_stats stat;

    nl_header = (struct nlmsghdr *) buffer;

    while (NLMSG_OK(nl_header, len)) {
        /* Check for error */
        if (nl_header->nlmsg_type == NLMSG_ERROR) {
            /* This is a netlink error msg */
            struct nlmsgerr *error = (struct nlmsgerr *) NLMSG_DATA(nl_header);
            if (error->error != 0) {
                syslog(LOG_ERR, "netlink msg error: %s\n", strerror(error->error));
                rc = false;
            }
            break;
        }

        /* Handle the response from the kernel */
        if_info = (ifinfomsg *) NLMSG_DATA(nl_header);

        /* Retrieve the attributes */
        attr = IFLA_RTA(if_info);
        attr_len = NLMSG_PAYLOAD(nl_header, sizeof(struct ifinfomsg));
        while (RTA_OK(attr, attr_len)) {
            /* Check the type of this valid attribute */
            switch (attr->rta_type)
            {
                case IFLA_IFNAME:
                    strncpy(stat.if_name, (char *)RTA_DATA(attr), MAX_IFNAME_LEN);
                    stat.if_name[MAX_IFNAME_LEN - 1] = '\0';
                    break;
                case IFLA_STATS:
                    memcpy(&stat.if_stats, (struct rtnl_link_stats *) RTA_DATA(attr), sizeof(struct rtnl_link_stats));
                    break;
                default:
                    break;
            }

            /* Get the next attribute */
            attr = RTA_NEXT(attr, attr_len);
        }

        /* Get the next netlink msg */
        nl_header = NLMSG_NEXT(nl_header, len);

        stats.push_back(stat);
    }

    return rc;
}

/*
 * Parse netlink link information
 * return TRUE if parsed succeed, or FALSE if an error occurred
 */
bool parse_netlink_link_info(char *buffer, int len, std::list<struct net_link_info> &info)
{
    struct nlmsghdr      *nl_header;
    struct ifinfomsg     *if_info;
    struct rtattr        *attr;
    int                  attr_len;
    bool                 rc = true;
    struct net_link_info tmp_info;

    nl_header = (struct nlmsghdr *) buffer;

    while (NLMSG_OK(nl_header, len)) {
        /* Check for error */
        if (nl_header->nlmsg_type == NLMSG_ERROR) {
            /* This is a netlink error msg */
            struct nlmsgerr *error = (struct nlmsgerr *) NLMSG_DATA(nl_header);
            if (error->error != 0) {
                syslog(LOG_ERR, "netlink msg error: %s\n", strerror(error->error));
                rc = false;
            }
            break;
        }

        /* Handle the response from the kernel */
        if_info = (ifinfomsg *) NLMSG_DATA(nl_header);
        memcpy(&tmp_info.ifla_address, if_info, sizeof(struct ifinfomsg));

        /* Retrive the attributes */
        attr = IFLA_RTA(if_info);
        attr_len = NLMSG_PAYLOAD(nl_header, sizeof(struct ifinfomsg));
        while (RTA_OK(attr, attr_len)) {
            /* Check the type of this valid attribute */
            switch (attr->rta_type)
            {
                case IFLA_IFNAME:
                    strncpy(tmp_info.ifla_ifname, (char *) RTA_DATA(attr), MAX_IFNAME_LEN);
                    tmp_info.ifla_ifname[MAX_IFNAME_LEN - 1] = '\0';
                    NL_DEBUG_PRINT(stderr, "device name: %s\n", (char *) RTA_DATA(attr));
                    break;
                case IFLA_MTU:
                    tmp_info.ifla_mtu = *(unsigned int *) RTA_DATA(attr);
                    NL_DEBUG_PRINT(stderr, "device MTU: %d\n", *(unsigned int *) RTA_DATA(attr));
                    break;
                case IFLA_QDISC:
                    strncpy(tmp_info.ifla_qdisc, (char *) RTA_DATA(attr), MAX_IF_QDISC);
                    tmp_info.ifla_qdisc[MAX_IF_QDISC - 1] = '\0';
                    NL_DEBUG_PRINT(stderr, "device Queueing discipline: %s\n", (char *) RTA_DATA(attr));
                    break;
                case IFLA_ADDRESS:
                    if (if_info->ifi_type == ARPHRD_ETHER) {
                        memcpy(&tmp_info.ifla_address, RTA_DATA(attr), sizeof(struct ether_addr));
                        NL_DEBUG_PRINT(stderr, "MAC address: %s\n", ether_ntoa((struct ether_addr *) RTA_DATA(attr)));
                    }
                    break;
                case IFLA_BROADCAST:
                    if (if_info->ifi_type == ARPHRD_ETHER) {
                        memcpy(&tmp_info.ifla_address, RTA_DATA(attr), sizeof(struct ether_addr));
                        NL_DEBUG_PRINT(stderr, "BROADCAST address: %s\n", ether_ntoa((struct ether_addr *) RTA_DATA(attr)));
                    }
                    break;
                case IFLA_STATS:
                    break;
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

    return rc;
}

/*
 * Parse netlink address information
 * return TRUE if parsed succeed, or FALSE if an error occurred
 */
bool parse_netlink_address_info(char *buffer, int len, std::list<struct net_address_info> &info)
{
    struct nlmsghdr         *nl_header;
    struct ifaddrmsg        *if_info;
    struct rtattr           *attr;
    int                     attr_len;
    bool                    rc = true;
    struct net_address_info tmp_info;

    nl_header = (struct nlmsghdr *) buffer;

    while (NLMSG_OK(nl_header, len)) {
        /* Check for error */
        if (nl_header->nlmsg_type == NLMSG_ERROR) {
            /* This is a netlink error msg */
            struct nlmsgerr *error = (struct nlmsgerr *) NLMSG_DATA(nl_header);
            if (error->error != 0) {
                syslog(LOG_ERR, "netlink msg error: %s\n", strerror(error->error));
                rc = false;
            }
            break;
        }

        /* Handle the response from the kernel */
        if_info = (ifaddrmsg *) NLMSG_DATA(nl_header);
        memcpy(&tmp_info.ifa_info, if_info, sizeof(tmp_info.ifa_info));

        /* Retrive the attributes */
        attr = IFLA_RTA(if_info);
        attr_len = NLMSG_PAYLOAD(nl_header, sizeof(struct ifinfomsg));
        while (RTA_OK(attr, attr_len)) {
            /* Check the type of this valid attribute */
            switch (attr->rta_type)
            {
                case IFA_ADDRESS:
                    memcpy(&tmp_info.ifa_address, RTA_DATA(attr), sizeof(struct in_addr));
                    NL_DEBUG_PRINT(stderr, "IFA_ADDRESS: %s\n", inet_ntoa(*(struct in_addr *) RTA_DATA(attr)));
                    break;
                case IFA_LOCAL:
                    memcpy(&tmp_info.ifa_local, RTA_DATA(attr), sizeof(struct in_addr));
                    NL_DEBUG_PRINT(stderr, "IFA_LOCAL: %s\n", inet_ntoa(*(struct in_addr *) RTA_DATA(attr)));
                    break;
                case IFA_LABEL:
                    strncpy(tmp_info.ifa_label, (char *) RTA_DATA(attr), MAX_IFNAME_LEN);
                    tmp_info.ifa_label[MAX_IFNAME_LEN - 1] = '\0';
                    NL_DEBUG_PRINT(stderr, "IFA_LABEL: %s\n", (char *) RTA_DATA(attr));
                    break;
                case IFA_BROADCAST:
                    memcpy(&tmp_info.ifa_broadcast, RTA_DATA(attr), sizeof(struct in_addr));
                    NL_DEBUG_PRINT(stderr, "IFA_BROADCAST: %s\n", inet_ntoa(*(struct in_addr *) RTA_DATA(attr)));
                    break;
                case IFA_ANYCAST:
                    memcpy(&tmp_info.ifa_anycast, RTA_DATA(attr), sizeof(struct in_addr));
                    NL_DEBUG_PRINT(stderr, "IFA_ANYCAST: %s\n", inet_ntoa(*(struct in_addr *) RTA_DATA(attr)));
                    break;
                case IFA_CACHEINFO:
                    memcpy(&tmp_info.ifa_cacheinfo, RTA_DATA(attr), sizeof(struct ifa_cacheinfo));
                    break;
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

    return rc;
}

/**
 *  get network statistics of all interface from kernel (pid: 0)
 */
bool get_interfaces_stats(std::list<struct net_interface_stats> &stats)
{
    int                fd;
    struct sockaddr_nl sa;
    struct nlmsghdr    *nl_header;
    char               buffer[BUF_SIZE];
    int                nbytes;
    int                rc = true;

    if ((fd = open_netlink_socket()) == -1) {
        syslog(LOG_ERR, "open_nl_socket failed\n");
        rc = false;
        goto error_exit;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = 0;
    sa.nl_groups = 0;

    if (bind_netlink_socket(fd, &sa, sizeof(sa)) == -1) {
        syslog(LOG_ERR, "bind_nl_socket failed\n");
        rc = false;
        goto error_exit;
    }

    if (send_netlink_request(fd, 0, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP) == -1) {
        syslog(LOG_ERR, "send_nl_get_request failed\n");
        rc = false;
        goto error_exit;
    }

    while ((nbytes = recv_netlink_response(fd, buffer, sizeof(buffer))) > 0) {
        nl_header = (struct nlmsghdr *) buffer;

        /* Got the complete response now */
        if (nl_header->nlmsg_type == NLMSG_DONE) {
            /* Ending of msg - no need to handle */
            break;
        }

        if (parse_netlink_interface_stats(buffer, nbytes, stats) == false) {
            syslog(LOG_ERR, "parse_netlink_data failed\n");
            rc = false;
            goto error_exit;
        }
    }

error_exit:

    if (fd != -1) {
        close(fd);
    }

    return rc;
}

bool get_interfaces_info(struct net_interfaces_info &info)
{
    int                fd;
    struct sockaddr_nl sa;
    struct nlmsghdr    *nl_header;
    char               buffer[BUF_SIZE];
    int                nbytes;
    int                rc = true;

    if ((fd = open_netlink_socket()) == -1) {
        syslog(LOG_ERR, "open_nl_socket failed\n");
        rc = false;
        goto error_exit;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = 0;
    sa.nl_groups = 0;

    if (bind_netlink_socket(fd, &sa, sizeof(sa)) == -1) {
        syslog(LOG_ERR, "bind_nl_socket failed\n");
        rc = false;
        goto error_exit;
    }

    // send get link request
    if (send_netlink_request(fd, 0, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP) == -1) {
        syslog(LOG_ERR, "send_nl_get_request failed\n");
        rc = false;
        goto error_exit;
    }

    while ((nbytes = recv_netlink_response(fd, buffer, sizeof(buffer))) > 0) {
        nl_header = (struct nlmsghdr *) buffer;
        if (nl_header->nlmsg_type == NLMSG_DONE) {
            /* Ending of msg - no need to handle */
            break;
        }

        if (parse_netlink_link_info(buffer, nbytes, info.if_links) == false) {
            syslog(LOG_ERR, "parse_netlink_data failed\n");
            rc = false;
            goto error_exit;
        }
    }

    // send get address request
    if (send_netlink_request(fd, 0, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP) == -1) {
        syslog(LOG_ERR, "send_nl_get_request failed\n");
        rc = false;
        goto error_exit;
    }

    while ((nbytes = recv_netlink_response(fd, buffer, sizeof(buffer))) > 0) {
        nl_header = (struct nlmsghdr *) buffer;
        if (nl_header->nlmsg_type == NLMSG_DONE) {
            /* Ending of msg - no need to handle */
            break;
        }

        if (parse_netlink_address_info(buffer, nbytes, info.if_addrs) == false) {
            syslog(LOG_ERR, "parse_netlink_data failed\n");
            rc = false;
            goto error_exit;
        }
    }

error_exit:

    if (fd != -1) {
        close(fd);
    }

    return rc;
}

