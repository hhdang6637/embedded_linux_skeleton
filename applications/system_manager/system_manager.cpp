#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "service_hiawatha.h"

#define CONFIG_DIR "/tmp/configs"

void system_manager_init()
{

    mkdir(CONFIG_DIR, 0755);
    // start web server
    service_hiawatha::getInstance()->init();
    service_hiawatha::getInstance()->start();

    system("web_handler");

#ifdef arm_vexpress_a9
    if ((access("/dev/mmcblk0", F_OK)) != -1 && (access("/mnt", F_OK) != -1)) {
        system("mount -t vfat /dev/mmcblk0 /mnt");
    }
#else
    if ((access("/dev/mmcblk0p2", F_OK)) != -1 && (access("/mnt", F_OK) != -1)) {
        system("mount -t vfat /dev/mmcblk0p2 /mnt");
    }

    if ((access("/dev/mmcblk0p3", F_OK)) != -1 && (access("/data", F_OK) != -1)) {
        system("mount -t ext4 /dev/mmcblk0p3 /data/");
    }
#endif
}
