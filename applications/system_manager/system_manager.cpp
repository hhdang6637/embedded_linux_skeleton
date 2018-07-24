#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <error.h>

#include <iostream>
#include <list>

#include "serviceHiawatha.h"
#include "simpleTimerSync.h"
#include "resourceCollector.h"

#define CONFIG_DIR "/tmp/configs"

void system_manager_init()
{

    mkdir(CONFIG_DIR, 0755);
    // start web server
    app::serviceHiawatha::getInstance()->init();
    app::serviceHiawatha::getInstance()->start();

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
    app::resourceCollector::getInstance()->cpu_do_collect();
#if 1
    std::list<cpu_stat_t>  cpu_history = app::resourceCollector::getInstance()->get_cpu_history();

    long double total_diff = 0;
    long double idle_diff = 0;

    cpu_stat_t pre, cur;
    cur = cpu_history.back();
    cpu_history.pop_back();
    pre = cpu_history.back();

    total_diff += cur.total - pre.total;
    idle_diff += cur.idle - pre.idle;

    char buffer[158];
    snprintf(buffer, sizeof(buffer), "cpu ide:%2.2Lf", idle_diff / total_diff * 100);
    std::cout << buffer;
    std::cout << std::endl;
#endif
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
