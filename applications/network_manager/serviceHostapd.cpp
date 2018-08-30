/*
 * serviceHostapd.cpp
 *
 *  Created on: Aug 30, 2018
 *      Author: hhdang
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

#include <fstream>

#include "serviceHostapd.h"

#define HOSTAPD_CONFIG_DIR "/tmp/configs/hostapd/"
#define HOSTAPD_PID_FILE "/var/run/hostapd.pid"
#define HOSTAPD_CONFIG_FILE HOSTAPD_CONFIG_DIR"hostapd.conf"

namespace app
{

serviceHostapd::serviceHostapd() : started(false)
{
    // TODO Auto-generated constructor stub

}

serviceHostapd::~serviceHostapd()
{
    // TODO Auto-generated destructor stub
}

serviceHostapd *serviceHostapd::s_instance = 0;

serviceHostapd* serviceHostapd::getInstance()
{
    if (s_instance == 0) {
        s_instance = new serviceHostapd();
    }

    return s_instance;
}

std::string serviceHostapd::service_name()
{
    static std::string service_name("hostapd");
    return service_name;
}

bool serviceHostapd::init()
{
    mkdir(HOSTAPD_CONFIG_DIR, 0755);

    std::ofstream hostapd_conf_file(HOSTAPD_CONFIG_FILE);
    if (hostapd_conf_file.is_open()) {
        hostapd_conf_file <<
                "logger_syslog=-1\n"
                "logger_syslog_level=0\n"
                "interface=wlan0\n"
                "hw_mode=g\n"
                "channel=10\n"
                "ieee80211d=1\n"
                "country_code=VN\n"
                "#ieee80211n=1\n"
                "wmm_enabled=1\n"
                "ssid=somename\n"
                "auth_algs=1\n"
                "wpa=2\n"
                "wpa_key_mgmt=WPA-PSK\n"
                "rsn_pairwise=CCMP\n"
                "wpa_passphrase=somepassword\n";

        hostapd_conf_file.close();
    }

    return true;
}

bool serviceHostapd::start()
{
    if (this->started == true) {
        return true;
    }

    std::string command;
    command = "/usr/sbin/hostapd ";
    command += "-B ";
    command += "-P ";
    command += HOSTAPD_PID_FILE;
    command += " ";
    command += HOSTAPD_CONFIG_FILE;

    system(command.c_str());

    this->started = true;

    return true;
}


bool serviceHostapd::stop()
{
    return true;
}

} /* namespace app */
