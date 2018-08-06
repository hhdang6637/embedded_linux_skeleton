/* Compile with: gcc -Wall -lfcgi fastcgi.c -o fastcgi
 */

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>

#include "netlink_socket.h"


int main(void) {
    struct net_device_stats stast = {};
    int if_index;
    double tx_rate = 0, rx_rate = 0;
    unsigned long tx_bytes_old = 0, rx_bytes_old = 0;

    if_index = if_nametoindex("eth0");

    printf("if_index: %d\n", if_index);

    while (1) {
        if (get_network_stats(if_index, &stast) != 0)
        {
            fprintf(stderr, "get_network_stats failed\n");
            return EXIT_FAILURE;
        }

        rx_rate = 0;
        if (stast.rx_bytes != 0 && (rx_bytes_old != stast.rx_bytes)) {
            rx_rate = stast.rx_bytes - rx_bytes_old;
            rx_bytes_old = stast.rx_bytes;
        }

        if (rx_rate > 1024 * 1024) {
            fprintf(stderr, "\t\tRx Rate: %uMbit/s\n", (unsigned) (rx_rate / (1024 * 1024)));
        } else if (rx_rate > 1024) {
            fprintf(stderr, "\t\tRx Rate: %uKbit/s\n", (unsigned) (rx_rate / 1024));
        } else
            fprintf(stderr, "\t\tRx Rate: %ubit/s\n", (unsigned) rx_rate);

        tx_rate = 0;
        if (stast.tx_bytes != 0 && (tx_bytes_old != stast.tx_bytes)) {
            tx_rate = stast.tx_bytes - tx_bytes_old;
            tx_bytes_old = stast.tx_bytes;
        }

        if (tx_rate > 1024 * 1024) {
            fprintf(stderr, "\t\tTx Rate: %uMbit/s\n", (unsigned) (tx_rate / (1024 * 1024)));
        } else if (tx_rate > 1024) {
            fprintf(stderr, "\t\tTx Rate: %uKbit/s\n", (unsigned) (tx_rate / 1024));
        } else
            fprintf(stderr, "\t\tTx Rate: %ubit/s\n", (unsigned) tx_rate);

        sleep(1);
    }

    return EXIT_SUCCESS;
}
