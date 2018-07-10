#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void system_manager_init() {

    // start web server
    system("mkdir /tmp/hiawatha");
    system("hiawatha -c /etc/hiawatha");

    if ((access("/dev/mmcblk0p2", F_OK)) != -1 && (access("/mnt", F_OK) != -1)) {
        system("mount -t vfat /dev/mmcblk0p2 /mnt");
    }

    if ((access("/dev/mmcblk0p3", F_OK)) != -1 && (access("/data", F_OK) != -1)) {
        system("mount -t ext4 /dev/mmcblk0p3 /data/");
    }
}
