/*
 * netlink_socket.h
 *
 *  Created on: Aug 6, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_
#define APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_

#include <list>

#define MAX_IFNAME_LEN 32

/*
 * Copy from kernel
 */
struct net_device_stats {
    unsigned long   rx_packets;             /* total packets received       */
    unsigned long   tx_packets;             /* total packets transmitted    */
    unsigned long   rx_bytes;               /* total bytes received         */
    unsigned long   tx_bytes;               /* total bytes transmitted      */
    unsigned long   rx_errors;              /* bad packets received         */
    unsigned long   tx_errors;              /* packet transmit problems     */
    unsigned long   rx_dropped;             /* no space in linux buffers    */
    unsigned long   tx_dropped;             /* no space available in linux  */
    unsigned long   multicast;              /* multicast packets received   */
    unsigned long   collisions;

    /* detailed rx_errors: */
    unsigned long   rx_length_errors;
    unsigned long   rx_over_errors;         /* receiver ring buff overflow  */
    unsigned long   rx_crc_errors;          /* recved pkt with crc error    */
    unsigned long   rx_frame_errors;        /* recv'd frame alignment error */
    unsigned long   rx_fifo_errors;         /* recv'r fifo overrun          */
    unsigned long   rx_missed_errors;       /* receiver missed packet       */

    /* detailed tx_errors */
    unsigned long   tx_aborted_errors;
    unsigned long   tx_carrier_errors;
    unsigned long   tx_fifo_errors;
    unsigned long   tx_heartbeat_errors;
    unsigned long   tx_window_errors;

    /* for cslip etc */
    unsigned long   rx_compressed;
    unsigned long   tx_compressed;
};

struct interface_info {
    struct net_device_stats if_stats;
    char                    if_name[MAX_IFNAME_LEN];
};

int open_netlink_socket();

int bind_netlink_socket(int fd, struct sockaddr_nl *sa, int sa_size);

int send_netlink_get_request(int fd, int ifi_index, int seq);

int recv_netlink_response(int fd, char *buffer, size_t buf_size);

bool parse_netlink_data(char *buffer, int len, std::list<struct interface_info> &info);

bool get_network_stats(std::list<struct interface_info> &info);

#endif /* APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_ */
