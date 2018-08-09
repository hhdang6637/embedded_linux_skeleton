/*
 * netlink_socket.h
 *
 *  Created on: Aug 6, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_
#define APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_

#include <list>

#include <net/ethernet.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <netinet/in.h>
#include <stdint.h>

#define MAX_IFNAME_LEN 32
#define MAX_IF_QDISC   32

struct net_interface_stats {
    struct rtnl_link_stats if_stats;
    char                   if_name[MAX_IFNAME_LEN];
};

struct net_link_info {
    struct ifinfomsg  ifla_info;
    struct ether_addr ifla_address;                // Interface L2 address
    struct ether_addr ifla_broadcast;              // L2 broadcast address.
    char              ifla_ifname[MAX_IFNAME_LEN]; // Device name.
    unsigned int      ifla_mtu;                    // MTU of the device.
    int               ifla_link;                   // Link type.
    char              ifla_qdisc[MAX_IF_QDISC];    // Queueing discipline.
};

struct net_address_info {
    struct ifaddrmsg     ifa_info;
    struct in_addr       ifa_address;               // Interface address
    struct in_addr       ifa_local;                 // Local address
    char                 ifa_label[MAX_IFNAME_LEN]; // Name of the interface
    struct in_addr       ifa_broadcast;             // Broadcast address.
    struct in_addr       ifa_anycast;               // Anycast address
    struct ifa_cacheinfo ifa_cacheinfo;             // Address information.
};

struct net_interfaces_info {
    std::list<struct net_link_info>    if_links;
    std::list<struct net_address_info> if_addrs;
};

int open_netlink_socket();

int bind_netlink_socket(int fd, struct sockaddr_nl *sa, int sa_size);

int send_netlink_request(int fd, int pid, uint16_t nlmsg_type, uint16_t nlmsg_flags);

int recv_netlink_response(int fd, char *buffer, size_t buf_size);

bool parse_netlink_interface_stats(char *buffer, int len, std::list<struct net_interface_stats> &stats);

bool parse_netlink_link_info(char *buffer, int len, std::list<struct net_link_info> &info);

bool parse_netlink_address_info(char *buffer, int len, std::list<struct net_address_info> &info);

bool get_interfaces_stats(std::list<struct net_interface_stats> &stats);

bool get_interfaces_info(struct net_interfaces_info &info);

#endif /* APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_ */
