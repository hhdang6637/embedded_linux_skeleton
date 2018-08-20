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

#define NTP_CONFIG_DIR  "/tmp/ntp/"
#define NTP_PID_FILE    "/var/run/ntpd.pid"

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

    std::ofstream ntpConfFile(NTP_CONFIG_DIR"ntp.conf");

    if (ntpConfFile.is_open()) {
        ntpConfFile <<
                "server 0.asia.pool.ntp.org\n"
                "server 1.asia.pool.ntp.org\n"
                "server 2.asia.pool.ntp.org\n"
                "server 3.asia.pool.ntp.org\n"
                "\n";

        ntpConfFile.close();
    }

    return true;
}

bool serviceNtp::start()
{
    std::string command;
    command = "/usr/sbin/ntpd -g -c " NTP_CONFIG_DIR "ntp.conf -p " NTP_PID_FILE;

    system(command.c_str());

    return true;
}

} /* namespace app */
