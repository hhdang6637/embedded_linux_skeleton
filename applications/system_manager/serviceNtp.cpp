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
    // TODO

    mkdir(NTP_CONFIG_DIR, 0755);

    return copy_file(NTP_PERSISTENT_CONFIG, NTP_CONFIG_DIR"ntp.conf");
}

bool serviceNtp::start()
{
    std::string command;
    command = "/usr/sbin/ntpd -g -c " NTP_CONFIG_DIR "ntp.conf -p " NTP_PID_FILE;

    system(command.c_str());

    return true;
}

bool serviceNtp::setNtpCfg(const ntpConfig_t &cfg)
{
    // TODO
    init();
    return start();
}

ntpConfig_t const &serviceNtp::getNtpCfg() const
{
    // TODO
    return ntpCfg;
}

} /* namespace app */
