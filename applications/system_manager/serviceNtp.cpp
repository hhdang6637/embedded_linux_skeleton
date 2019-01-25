/*
 * serviceNtp.cpp
 *
 *  Created on: Aug 16, 2018
 *      Author: hhdang
 */

#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>

#include "serviceNtp.h"
#include "utilities.h"

#define NTP_PERSISTENT_CONFIG   "/data/ntp.conf"
#define NTP_CONFIG_DIR  "/tmp/ntp/"
#define NTP_PID_FILE    "/var/run/ntpd.pid"

static app::ntpConfig_t ntpCfg;

namespace app
{

serviceNtp::serviceNtp()
{
    // TODO Auto-generated constructor stub

}

serviceNtp::~serviceNtp()
{
    // TODO Auto-generated destructor stub
}

std::string serviceNtp::service_name()
{
    static std::string service_name("ntpd");
    return service_name;
}

serviceNtp *serviceNtp::s_instance = 0;

serviceNtp* serviceNtp::getInstance()
{
    if (s_instance == 0) {
        s_instance = new serviceNtp();
    }

    return s_instance;
}

bool serviceNtp::init()
{
    mkdir(NTP_CONFIG_DIR, 0755);
    std::ofstream ntp_config_file(NTP_CONFIG_DIR"ntp.conf");
    if(ntp_config_file.is_open())
    {
        ntp_config_file << "server " << ntpCfg.ntp_server << "\n";

        ntp_config_file.close();
    }
    return true;
}

bool serviceNtp::stop()
{
    // verify pid file and stop openvpn service
    if (access("/var/run/ntpd.pid", F_OK) != -1) {
        if(system("killall ntpd") == 0)
            return true;
    }
    return false;
}


bool serviceNtp::start()
{
    std::string command;
    command = "/usr/sbin/ntpd -g -c " NTP_CONFIG_DIR "ntp.conf -p " NTP_PID_FILE;

    if(system(command.c_str()) == 0)
        return true;

    return false;
}

bool serviceNtp::setNtpCfg(const ntpConfig_t &cfg)
{
    // TODO validate cfg

    stop();

    if(cfg.state != 0)
    {
        memset(&ntpCfg, 0, sizeof(ntpCfg));
        memcpy(&ntpCfg, &cfg, sizeof(cfg));
        init();
        return start();
    }

    ntpCfg.state = cfg.state;

    return true;
}

ntpConfig_t const &serviceNtp::getNtpCfg() const
{
    // TODO
    syslog(LOG_INFO, "serviceNtp::getNtpCfg: enbale: %d\n", ntpCfg.state);
    syslog(LOG_INFO, "serviceNtp::getNtpCfg: ntp_server: %s\n", ntpCfg.ntp_server);
    return ntpCfg;
}

} /* namespace app */
