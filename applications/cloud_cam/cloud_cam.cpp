#include <string.h>
#include <syslog.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "simpleTimerSync.h"
#include "netlink_socket.h"
#include "utilities.h"

typedef struct
{
    char macs[6];
    char mac_vendor[64];
} mac_addr;

typedef struct
{
    unsigned char ips[4];
    mac_addr      mac;
} host_info;

#define PRIVOXY_CONFIG_DIR "/tmp/configs/privoxy/"

static std::list<std::string> local_subnets_new;
static std::list<host_info> local_addr_found;
static int interval_scan = (1000*60*60)*6;

static void start_privoxy(void);
static void update_local_subnet_addresses(void);
static void split_subnet24(const char* subnet, std::list<std::string> &local_addr_found);
static void scan_camera_rtsp(const char* subnet, std::list<host_info> &list_found_ips);

static void start_nmap_thread(void);
static void *nmap_thread_work(void *context);


void cloud_cam_service_loop()
{
    fd_set read_fds;

    start_privoxy();

    // wait the network wakeup
    sleep(60);

    app::simpleTimerSync *timer = app::simpleTimerSync::getInstance();
    timer->init(1000);
    timer->addCallback(interval_scan, update_local_subnet_addresses);
    timer->start();

    std::list<int> listReadFd;
    listReadFd.push_back(timer->getTimterFd());

    update_local_subnet_addresses();

    while (1) {
        int maxfd = build_fd_sets(&read_fds, listReadFd);

        int activity = select(maxfd + 1, &read_fds, NULL, NULL, NULL);

        switch (activity)
        {
        case -1:
            if (errno != EINTR) {
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

static void update_local_subnet_addresses()
{
    FILE* f_stream;
    char line[512];
    int len;

    if (local_subnets_new.size() > 0) {
        syslog(LOG_INFO, "the list new subnet still available");
        return;
    }

    f_stream = popen("ip -o -f inet addr show | awk '/scope global/ {print $4}'", "r");

    if (f_stream) {
        while (fgets(line, sizeof(line), f_stream) != NULL) {
            len = strlen(line);
            if (line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }
            split_subnet24(line, local_subnets_new);
        }
        pclose(f_stream);
    }

    if (local_subnets_new.size() > 0) {
        start_nmap_thread();
    } else {
        syslog(LOG_INFO, "Cannot found any ipv4 addresses");
    }
}

void start_nmap_thread(void)
{
    pthread_t nmapThread;
    pthread_attr_t  thread_attr;
    pthread_attr_init (&thread_attr);
    pthread_create(&nmapThread, &thread_attr, nmap_thread_work, NULL);
    pthread_attr_destroy(&thread_attr);
}

void *nmap_thread_work(void *context)
{
    syslog(LOG_NOTICE, "nmap_thread_work start");

    local_addr_found.clear();

    while(local_subnets_new.size() > 0)
    {
        std::string subnet = local_subnets_new.back();
        scan_camera_rtsp(subnet.c_str(), local_addr_found);
        local_subnets_new.pop_back();
    }

    if (local_addr_found.size() > 0) {
        syslog(LOG_NOTICE, "nmap found:");
        for (std::list<host_info>::iterator i = local_addr_found.begin(); i != local_addr_found.end(); ++i) {
            syslog(LOG_NOTICE, "%hhu.%hhu.%hhu.%hhu", i->ips[0], i->ips[1], i->ips[2], i->ips[3]);
        }
    } else {
        syslog(LOG_NOTICE, "nmap found nothing");
    }

    syslog(LOG_NOTICE, "nmap_thread_work done");
    return NULL;
}

void scan_camera_rtsp(const char* subnet, std::list<host_info> &list_found_ips)
{
    char nmap_cmd[256];
    char buff[512];
    FILE* nmap_out_stream;
    host_info host;

    memset(&host, 0, sizeof(host));

    snprintf(nmap_cmd, 256, "nmap -n -T5 %s -p T:554 --open -oN -", subnet);

    syslog(LOG_NOTICE, "nmap: %s", nmap_cmd);

    nmap_out_stream = popen(nmap_cmd, "r");

    if (nmap_out_stream) {
        while (fgets(buff, sizeof(buff), nmap_out_stream) != NULL) {
            unsigned char ips[4];
            char macs[6];
            char mac_vendor[64];

            if (sscanf(buff, "Nmap scan report for %hhu.%hhu.%hhu.%hhu", &ips[0], &ips[1], &ips[2], &ips[3]) == 4) {

                if (host.ips[0] != 0) {
                    // store the old host info
                    list_found_ips.push_back(host);
                }

                memset(&host, 0, sizeof(host));
                memcpy(host.ips, ips, 4);
            } else if (sscanf(buff, "MAC Address: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %[^\t\n]", &macs[0], &macs[1], &macs[2],
                    &macs[3], &macs[4], &macs[5], mac_vendor) == 7) {
                memcpy(host.mac.macs, macs, 6);
                memcpy(host.mac.mac_vendor, mac_vendor, 64);
            }
        }

        if (host.ips[0] != 0) {
            // store the old host info
            list_found_ips.push_back(host);
        }

        pclose(nmap_out_stream);
    }
}

void split_subnet24(const char* subnet, std::list<std::string> &local_addr_found)
{
    unsigned char ips[4];
    int subnet_len;

    if (sscanf(subnet, "%hhu.%hhu.%hhu.%hhu/%d", &ips[0], &ips[1], &ips[2], &ips[3], &subnet_len) != 5)
    {
        syslog(LOG_WARNING, "subnet %s is invalid", subnet);
        return;
    }

    if (subnet_len >= 32 || subnet_len < 16)
    {
        syslog(LOG_WARNING, "subnet %s is invalid", subnet);
        return;
    }

    if (subnet_len >= 24)
    {
        local_addr_found.push_back(subnet);
        return;
    }

    int bits = 24 - subnet_len;

    unsigned char ip2 = (ips[2] >> bits) << bits;

    int i;
    char newsubnet[64];
    for (i = 0; i < pow(2, bits); ++i) {
        snprintf(newsubnet, sizeof(newsubnet), "%d.%d.%d.0/24",
                ips[0], ips[1], ip2 + i);
        local_addr_found.push_back(newsubnet);
    }
}

static void start_privoxy()
{
    FILE *f;

    mkdir(PRIVOXY_CONFIG_DIR, 0755);

    if ((f = fopen(PRIVOXY_CONFIG_DIR"config", "w")) == NULL) {
            syslog(LOG_EMERG, "Cannot add default users to linux\n");
            return;
    }

    fprintf(f,
        "#forward-socks4a / 127.0.0.1:9050 .\n"
        "#confdir /data/privoxy\n"
        "#logdir /var/log/privoxy\n"
        "#actionsfile default.action   # Main actions file\n"
        "#actionsfile user.action      # User customizations\n"
        "#filterfile default.filter\n"
        "#logfile logfile\n"
        "#debug   4096 # Startup banner and warnings\n"
        "#debug   8192 # Errors - *we highly recommended enabling this*\n"
        "#user-manual /usr/share/doc/privoxy/user-manual\n"
        "listen-address  0.0.0.0:8080\n"
        "#toggle  1\n"
        "#enable-remote-toggle 0\n"
        "#enable-edit-actions 0\n"
        "#enable-remote-http-toggle 0\n"
        "#buffer-limit 4096\n"
    );

    fclose(f);

    syslog(LOG_NOTICE, "start privoxy service");
    system("/usr/sbin/privoxy "PRIVOXY_CONFIG_DIR"config");
}
