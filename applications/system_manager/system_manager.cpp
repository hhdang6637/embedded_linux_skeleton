#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <syslog.h>
#include <error.h>

#include <iostream>
#include <list>

#include "serviceHiawatha.h"
#include "simpleTimerSync.h"
#include "resourceCollector.h"
#include "rpcUnixServer.h"
#include "rpcMessageAddr.h"
#include "rpcMessageCpuHistory.h"

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

    app::rpcMessageAddr addr = app::rpcMessageAddr::getRpcMessageAddrbyType(
            app::rpcMessageAddr::rpcMessageAddrType::system_manager_addr_t);

    if (app::rpcUnixServer::getInstance()->openServer(addr) != true) {
        syslog(LOG_ERR, "cannot open unix socket server");
        exit(EXIT_FAILURE);
    }
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

static void cpuHistoryCollect() {
    app::resourceCollector::getInstance()->cpu_do_collect();
}

static bool get_cpu_history_handler(int socker_fd) {
    app::rpcMessageCpuHistory msgCpuHistory;
    if (msgCpuHistory.deserialize(socker_fd)) {
        std::list<cpu_stat_t> cpu_history = app::resourceCollector::getInstance()->get_cpu_history();
        msgCpuHistory.set_cpu_history(cpu_history);
        return msgCpuHistory.serialize(socker_fd);
    }
    return false;
}

void system_manager_service_loop()
{
    fd_set read_fds;
    app::rpcUnixServer *rpcServer = app::rpcUnixServer::getInstance();
    int server_socket = rpcServer->get_socket();
    rpcServer->registerMessageHandler(app::rpcMessage::rpcMessageType::get_cpu_history, get_cpu_history_handler);

    app::simpleTimerSync *timer = app::simpleTimerSync::getInstance();
    timer->init(1000);
    timer->addCallback(1000, cpuHistoryCollect);
    timer->start();

    std::list<int> listReadFd;
    listReadFd.push_back(timer->getTimterFd());
    listReadFd.push_back(server_socket);

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

                 if (FD_ISSET(server_socket, &read_fds)) {
                     if (rpcServer->doReply() == false) {
                        syslog(LOG_ERR, "fail to handle new connection");
                     }
                 }

             }
        }
    }
}
