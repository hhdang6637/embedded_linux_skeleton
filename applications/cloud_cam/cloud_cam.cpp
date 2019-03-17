#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/signalfd.h>

#include <fstream>
#include <sstream>

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

#define RTSP_PORT 554
#define RTSP_OK_STR "RTSP/1.0 200 OK"
#define PRIVOXY_CONFIG_DIR "/tmp/configs/privoxy/"
#define OVPN_PROFILE "/tmp/openvpn.ovpn"

// LOCAL
static std::list<std::string> local_subnets_new;
static std::list<host_info> local_addr_found;
static int interval_scan = (1000*60*60)*6;

// CLOUD request
static std::list<std::string> cloud_subnets_new;
static std::list<host_info> cloud_addr_found;

static bool start_privoxy(void);
static void update_local_subnet_addresses(void);
static void split_subnet24(const char* subnet, std::list<std::string> &local_addr_found);
static void scan_camera_rtsp(const char* subnet, std::list<host_info> &list_found_ips);

static void start_nmap_thread(void *thread_func(void *context));
static void *nmap_thread_work_local(void *context);
static void *nmap_thread_work_cloud(void *context);

static int init_sigfd();

bool cloud_request_scan(const char*subnet);
static void simulate_cloud_request_scan();
static bool valid_rtsp_protocol(const host_info *host);
static bool start_openvpn_client();
static void get_tun0_address(std::string &ip);

void cloud_cam_service_loop()
{
    bool stop_flag = false;
    fd_set read_fds;
    struct timeval tv;
    bool privoxy_running, ovpn_running;

    // wait the network wakeup
    sleep(60);

    ovpn_running = start_openvpn_client();
    privoxy_running = start_privoxy();

    app::simpleTimerSync *timer = app::simpleTimerSync::getInstance();
    timer->init(1000);
    timer->addCallback(interval_scan, update_local_subnet_addresses);
    timer->start();

    std::list<int> listReadFd;
    listReadFd.push_back(timer->getTimterFd());

    int sigfd = init_sigfd();
    if (sigfd > 0)
    {
        listReadFd.push_back(sigfd);
    }

    update_local_subnet_addresses();

    while (!stop_flag) {
        int maxfd = build_fd_sets(&read_fds, listReadFd);

        if (!ovpn_running) {
            ovpn_running = start_openvpn_client();
        }

        if (!privoxy_running && ovpn_running) {
            privoxy_running = start_privoxy();
        }

        tv.tv_sec = 60;
        tv.tv_usec = 0;

        int activity = select(maxfd + 1, &read_fds, NULL, NULL, &tv);

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
            if (FD_ISSET(sigfd, &read_fds)) {
                /* signal handling */
                struct signalfd_siginfo fdsi;
                ssize_t s = read(sigfd, &fdsi, sizeof(fdsi));
                if (s != sizeof(fdsi)) {
                    syslog(LOG_WARNING, "Could not read from signal fd");
                    continue;
                }
                switch(fdsi.ssi_signo) {
                case SIGUSR1:
                    /* simulate cloud request */
                    simulate_cloud_request_scan();
                    break;
                case SIGCHLD:
                    syslog(LOG_NOTICE, "recive SIGCHLD ssi_pid = %u", fdsi.ssi_pid);
                     break;
                default:
                    stop_flag = true;
                    break;
                }
            }
        }
        }
    }
}

static bool start_openvpn_client()
{
    if (system("/usr/sbin/openvpn --config " OVPN_PROFILE " --daemon") != 0) {
        syslog(LOG_ERR, "cannot start VPN");
        return false;
    }

    return true;
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
        start_nmap_thread(nmap_thread_work_local);
    } else {
        syslog(LOG_INFO, "Cannot found any ipv4 addresses");
    }
}

static void start_nmap_thread(void *thread_func(void *context))
{
    pthread_t nmapThread;
    pthread_attr_t  thread_attr;
    pthread_attr_init (&thread_attr);
    pthread_create(&nmapThread, &thread_attr, thread_func, NULL);
    pthread_attr_destroy(&thread_attr);
}

// output: "camera_list": ["192.168.2.3", "192.168.2.4", "192.168.3.4"]
static void camera_list_to_json_array(std::list<host_info> &list, std::string &str)
{
    size_t counter = 0;
    char ip[32];

    syslog(LOG_NOTICE, "nmap camera_list_to_json_array");

    str = "\"camera_list\": [";
    for (auto const& i : list) {
        snprintf(ip, sizeof(ip), "\"%hhu.%hhu.%hhu.%hhu\"", i.ips[0], i.ips[1], i.ips[2], i.ips[3]);
        str += ip;

        if (++counter < list.size()) {
            str += ",";
        }
    }
    str += "]";

    syslog(LOG_NOTICE, "str: %s", str.c_str());
}

static void send_camera_list_to_cloud(const std::string &str)
{
    std::ostringstream cmd;
    std::string tun0_addr;

    get_tun0_address(tun0_addr);

    cmd << "curl -H 'Content-type: application/json' -X POST -d '";
    cmd << "{\"gateway_ip\":\"" << tun0_addr << "\", ";
    cmd << str;
    cmd << "}'";
    cmd << " http://10.8.0.1:5000/gateways";

    if (system(cmd.str().c_str()) != 0) {
        syslog(LOG_ERR, "Cannot send camera list to cloud!");
        return;
    }

    syslog(LOG_NOTICE, "Send camera list to cloud succeed: %s", cmd.str().c_str());
}

static void *nmap_thread_work_local(void *context)
{
    std::list<host_info> tmp_addr_found;
    syslog(LOG_NOTICE, "nmap_thread_work_local start");

    local_addr_found.clear();

    while(local_subnets_new.size() > 0)
    {
        std::string subnet = local_subnets_new.back();
        scan_camera_rtsp(subnet.c_str(), tmp_addr_found);
        local_subnets_new.pop_back();
    }

    for (std::list<host_info>::iterator i = tmp_addr_found.begin(); i != tmp_addr_found.end(); ++i) {
        if (valid_rtsp_protocol(&*i)) {
            local_addr_found.push_back(*i);
        }
    }

    if (local_addr_found.size() > 0) {
        std::string camera_list;
        camera_list_to_json_array(local_addr_found, camera_list);

        syslog(LOG_NOTICE, "nmap found: %s", camera_list.c_str());

        send_camera_list_to_cloud(camera_list);
    } else {
        syslog(LOG_NOTICE, "nmap found nothing");
    }

    syslog(LOG_NOTICE, "nmap_thread_work_local done");
    return NULL;
}

static void *nmap_thread_work_cloud(void *context)
{
    std::list<host_info> tmp_addr_found;
    syslog(LOG_NOTICE, "nmap_thread_work_cloud start");

    cloud_addr_found.clear();

    while(cloud_subnets_new.size() > 0)
    {
        std::string subnet = cloud_subnets_new.back();
        scan_camera_rtsp(subnet.c_str(), tmp_addr_found);
        cloud_subnets_new.pop_back();
    }

    if (tmp_addr_found.size() > 0) {
        syslog(LOG_NOTICE, "nmap found %d ips address, we are going to filter them", tmp_addr_found.size());
    }

    for (std::list<host_info>::iterator i = tmp_addr_found.begin(); i != tmp_addr_found.end(); ++i) {
        if (valid_rtsp_protocol(&*i)) {
            cloud_addr_found.push_back(*i);
        }
    }

    if (cloud_addr_found.size() > 0) {
        std::string camera_list;
        camera_list_to_json_array(cloud_addr_found, camera_list);

        syslog(LOG_NOTICE, "nmap found: %s", camera_list.c_str());
        send_camera_list_to_cloud(camera_list);
    } else {
        syslog(LOG_NOTICE, "nmap found nothing");
    }

    syslog(LOG_NOTICE, "nmap_thread_work_cloud done");
    return NULL;
}

static void scan_camera_rtsp(const char* subnet, std::list<host_info> &list_found_ips)
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
                    // validate & store the old host info
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
            // validate & store the old host info
            list_found_ips.push_back(host);
        }

        pclose(nmap_out_stream);
    }
}

static void split_subnet24(const char* subnet, std::list<std::string> &local_addr_found)
{
    unsigned char ips[4];
    int subnet_len;
    char newsubnet[64];
    int i;

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
        snprintf(newsubnet, sizeof(newsubnet), "%d.%d.%d.%d/%d",
                ips[0], ips[1], ips[2], ips[3], subnet_len);
        local_addr_found.push_back(newsubnet);
        return;
    }

    int bits = 24 - subnet_len;

    unsigned char ip2 = (ips[2] >> bits) << bits;

    for (i = 0; i < pow(2, bits); ++i) {
        snprintf(newsubnet, sizeof(newsubnet), "%d.%d.%d.0/24",
                ips[0], ips[1], ip2 + i);
        local_addr_found.push_back(newsubnet);
    }
}

static void get_tun0_address(std::string &ip)
{
    struct net_interfaces_info info;

    get_interfaces_info(info);

    for (auto &ifo : info.if_addrs) {
        if (strcmp(ifo.ifa_label, "tun0") == 0) {
            ip = inet_ntoa(ifo.ifa_local);
        }
    }
}

static bool start_privoxy()
{
    std::string ip;

    get_tun0_address(ip);

    if (ip.empty()) {
        syslog(LOG_ERR, "VPN tunnel has not been established");
        return false;
    }

    mkdir(PRIVOXY_CONFIG_DIR, 0755);

    std::ofstream privoxy_cfg(PRIVOXY_CONFIG_DIR "config");

    if (privoxy_cfg.is_open()) {

        privoxy_cfg << "#forward-socks4a / 127.0.0.1:9050 .\n"
                       "#confdir /data/privoxy\n"
                       "#logdir /var/log/privoxy\n"
                       "#actionsfile default.action   # Main actions file\n"
                       "#actionsfile user.action      # User customizations\n"
                       "#filterfile default.filter\n"
                       "#logfile logfile\n"
                       "#debug   4096 # Startup banner and warnings\n"
                       "#debug   8192 # Errors - *we highly recommended enabling this*\n"
                       "#user-manual /usr/share/doc/privoxy/user-manual\n"
                       "listen-address " << ip << ":8080\n"
                       "#toggle  1\n"
                       "#enable-remote-toggle 0\n"
                       "#enable-edit-actions 0\n"
                       "#enable-remote-http-toggle 0\n"
                       "#buffer-limit 4096\n";

        privoxy_cfg.close();
    }

    if (system("/usr/sbin/privoxy " PRIVOXY_CONFIG_DIR "config") != 0) {
        syslog(LOG_ERR, "Cannot start privoxy service");
        return false;
    }

    syslog(LOG_NOTICE, "Started privoxy service");
    return true;
}

static int init_sigfd()
{
    int sigfd;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        syslog(LOG_WARNING, "Could not init sigprocmask");
        return -1;
    }
    sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sigfd < 0) {
        syslog(LOG_WARNING, "Could not init signal handling");
        return -1;
    }
    return sigfd;
}

// requests from outside

bool cloud_request_scan(const char*subnet) {

    if (cloud_subnets_new.size() > 0) {
        syslog(LOG_INFO, "the cloud list new subnet still available");
        return false;
    }

    split_subnet24(subnet, cloud_subnets_new);

    if (cloud_subnets_new.size() > 0) {
        start_nmap_thread(nmap_thread_work_cloud);
    } else {
        syslog(LOG_INFO, "Cannot found any ipv4 addresses in cloud request");
        return false;
    }

    return true;
}

static void simulate_cloud_request_scan()
{
    char line[256];
    FILE *f;

    if (cloud_subnets_new.size() > 0) {
        syslog(LOG_INFO, "the cloud list new subnet still available");
        return;
    }

    f = fopen("/tmp/cloud_request", "r");

    if (f == NULL) {
        syslog(LOG_ERR, "cannot open: %s", "/tmp/cloud_request");
        return;
    }

    while (fgets(line, sizeof(line), f) > 0) {
        int len = strlen(line);
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        split_subnet24(line, cloud_subnets_new);
    }

    fclose(f);

    if (cloud_subnets_new.size() > 0) {
        start_nmap_thread(nmap_thread_work_cloud);
    } else {
        syslog(LOG_INFO, "Cannot found any ipv4 addresses in cloud request");
        return;
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////

static bool send_rtsp_describe_pkt(int fd, const char* ip)
{
    char buffer[1024] = { 0 };
    std::string describe_pkt = "DESCRIBE rtsp://" + std::string(ip) + " RTSP/1.0\r\nCSeq: 2\r\n";

    if (send(fd, describe_pkt.c_str(), strlen(describe_pkt.c_str()), 0) == -1) {
        return false;
    }

    if (recv(fd, buffer, sizeof(buffer), 0) == -1) {
        return false;
    }

    if (strncmp(buffer, RTSP_OK_STR, strlen(RTSP_OK_STR)) == 0) {
        return true;
    }

    return false;
}

static bool send_rtsp_option_pkt(int fd)
{
    char buffer[1024] = { 0 };
    std::string option_pkt = "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n";

    if (send(fd, option_pkt.c_str(), strlen(option_pkt.c_str()), 0) == -1) {
        return false;
    }

    if (recv(fd, buffer, sizeof(buffer), 0) == -1) {
        return false;
    }

    if (strncmp(buffer, RTSP_OK_STR, strlen(RTSP_OK_STR)) == 0) {
        return true;
    }

    return false;
}

static bool valid_rtsp_protocol(const host_info *host)
{
    int fd;
    struct timeval tv;
    struct sockaddr_in serv_addr = { 0 };
    char ip[32];
    bool ret = false;

    snprintf(ip, sizeof(ip), "%hhu.%hhu.%hhu.%hhu", host->ips[0], host->ips[1], host->ips[2], host->ips[3]);

    syslog(LOG_NOTICE, "valid_rtsp_protocol(\"%hhu.%hhu.%hhu.%hhu\")",
        host->ips[0], host->ips[1], host->ips[2], host->ips[3]);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        goto failed;
    }

    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(RTSP_PORT);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        goto failed;
    }

    if (connect(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
        goto failed;
    }

    if (send_rtsp_describe_pkt(fd, ip) && send_rtsp_option_pkt(fd)) {
        ret = true;
    }

failed:
    if (fd != -1) {
        close(fd);
    }

    return ret;
}
