/*
 * netlink_socket.h
 *
 *  Created on: Aug 6, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_
#define APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_

/*
 * Copy from kernel
 */
struct net_device_stats
{
    unsigned long rx_packets;
    unsigned long tx_packets;
    unsigned long rx_bytes;
    unsigned long tx_bytes;
    unsigned long rx_errors;
    unsigned long tx_errors;
    unsigned long rx_dropped;
    unsigned long tx_dropped;
    unsigned long multicast;
    unsigned long collisions;
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;
    unsigned long rx_crc_errors;
    unsigned long rx_frame_errors;
    unsigned long rx_fifo_errors;
    unsigned long rx_missed_errors;
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
    unsigned long rx_compressed;
    unsigned long tx_compressed;
};

int open_nl_socket();

int bind_nl_socket(int fd, struct sockaddr_nl *sa, int size);

int send_nl_get_request(int fd, int ifi_index, const struct sockaddr_nl *sa, int size, int seq);

int recv_nl_response(int fd, char *buffer, int size);

void parse_nl_data(char *buffer, int len, struct net_device_stats *stats);

int get_network_stats(int ifi_index, struct net_device_stats *stats);

#endif /* APPLICATIONS_LIB_APP_NETLINK_SOCKET_H_ */
