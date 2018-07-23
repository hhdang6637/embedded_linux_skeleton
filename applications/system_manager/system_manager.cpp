#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <error.h>

#include <iostream>
#include <list>

#include "simpleTimerSync.h"
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

static int build_fd_sets(fd_set *read_fds, std::list<int> &fds)
{
    int max = 0;
    FD_ZERO(read_fds);

    for (auto &i : fds) {
        FD_SET(i, read_fds);
        if (max < i) {
            max = i;
        }
    }
    return max;
}

static void testTimerCallback() {
    // do nothing
}

void system_manager_service_loop()
{
    fd_set read_fds;

    app::simpleTimerSync *timer = app::simpleTimerSync::getInstance();
    timer->init(1000);
    timer->addCallback(1000, testTimerCallback);

    timer->start();

    std::list<int> listReadFd;
    listReadFd.push_back(timer->getTimterFd());

    while(1) {
        int maxfd = build_fd_sets(&read_fds, listReadFd);

        int activity = select(maxfd + 1, &read_fds, NULL, NULL, NULL);

        switch (activity) {
             case -1:
                 if(errno != EINTR) {
                     exit(EXIT_FAILURE);
                 }
                 break;
             case 0:
               // TODO
               continue;

             default:
             {
                 if (FD_ISSET(timer->getTimterFd(), &read_fds)) {
                     timer->do_schedule();
                 }
             }
        }
    }
}
