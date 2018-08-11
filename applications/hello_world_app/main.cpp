/* Compile with: gcc -Wall -lfcgi fastcgi.c -o fastcgi
 */

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>

#include "netlink_socket.h"


int main(void) {
    struct net_interfaces_info info;

    if (get_interfaces_info(info) == false) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
