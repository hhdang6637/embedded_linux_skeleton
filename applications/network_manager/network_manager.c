#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>

static bool _network_manager_wake_up(const char* interfaceName) {
    struct ifreq    ifr;
    int             socket_fd;
    bool            rc = true;

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (socket_fd == -1) {
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));

    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", interfaceName);
    ifr.ifr_flags = IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST;

    if (ioctl(socket_fd, SIOCSIFFLAGS, &ifr) == -1) {
        perror("cannot wake up interaface");
        rc = false;
        goto exit;
    }

exit:
    close(socket_fd);
    return rc;
}

void network_manager_init() {

    // TODO

    sleep(5);

    // start network interface eth0
    if (_network_manager_wake_up("eth0")) {
        // start udhcp
        system("udhcpc eth0");
    }

    // start web server
    system("hiawatha -c /etc/hiawatha");

    if ((access("/dev/mmcblk0p2", F_OK)) != -1 && (access("/mnt", F_OK) != -1)) {
        system("mount -t vfat /dev/mmcblk0p2 /mnt");
    }

    if ((access("/dev/mmcblk0p3", F_OK)) != -1 && (access("/data", F_OK) != -1)) {
        system("mount -t ext4 /dev/mmcblk0p3 /data/");
    }
}
