/*
 * rpc_unix.cpp
 *
 *  Created on: Jul 22, 2018
 *      Author: hhdang
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "rpc_unix.h"

int open_server_socket(const char*socket_path)
{
    int server_fd = -1;
    struct sockaddr_un addr;

    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*socket_path == '\0') {
        *addr.sun_path = '\0';
    } else {
        strncpy(addr.sun_path + 1, socket_path + 1, sizeof(addr.sun_path) - 2);
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
        unlink(socket_path);
    }

    if (bind(server_fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        goto error_exit;
    }

    if (listen(server_fd, 5) == -1) {
        goto error_exit;
    }

    return server_fd;

error_exit:

    if (server_fd != -1) {
        close(server_fd);
    }

    return -1;
}
int connect_to_server(const char*socket_path)
{
    int fd = -1;
    struct sockaddr_un addr;

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*socket_path == '\0') {
      *addr.sun_path = '\0';
      strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
    } else {
      strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        goto error_exit;
    }

error_exit:

    if (fd != -1) {
        close(fd);
    }

    return -1;
}

