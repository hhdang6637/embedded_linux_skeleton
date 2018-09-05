/*
 * serviceDnsmasq.cpp
 *
 *  Created on: Aug 30, 2018
 *      Author: hhdang
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

#include <fstream>

#include "serviceDnsmasq.h"

#define DNSMASQ_CONFIG_DIR "/tmp/configs/dnsmasq/"
#define DNSMASQ_PID_FILE "/var/run/dnsmasq.pid"
#define DNSMASQ_CONFIG_FILE DNSMASQ_CONFIG_DIR"dnsmasq.conf"

namespace app
{

serviceDnsmasq::serviceDnsmasq() :
        started(false)
{
    // TODO Auto-generated constructor stub

}

serviceDnsmasq::~serviceDnsmasq()
{
    // TODO Auto-generated destructor stub
}

serviceDnsmasq *serviceDnsmasq::s_instance = 0;

serviceDnsmasq* serviceDnsmasq::getInstance()
{
    if (s_instance == 0) {
        s_instance = new serviceDnsmasq();
    }

    return s_instance;
}

std::string serviceDnsmasq::service_name()
{
    static std::string service_name("dnsmasq");
    return service_name;
}

bool serviceDnsmasq::init()
{
    mkdir(DNSMASQ_CONFIG_DIR, 0755);

    std::ofstream dnsmasq_conf_file(DNSMASQ_CONFIG_FILE);
    if (dnsmasq_conf_file.is_open()) {
        dnsmasq_conf_file <<
                "# disables dnsmasq reading any other files like /etc/resolv.conf for nameservers\n"
                "no-resolv\n"
                "# Interface to bind to\n"
                "interface=wlan0\n"
                "# Specify starting_range,end_range,lease_time\n"
                "dhcp-range=10.0.0.3,10.0.0.20,1h\n"
                "# dns addresses to send to the clients\n"
                "server=8.8.8.8\n"
                "server=8.8.4.4\n";
        dnsmasq_conf_file.close();
    }

    return true;
}

bool serviceDnsmasq::start()
{
    if (this->started == true) {
        return true;
    }

    std::string command;
    command = "/usr/sbin/dnsmasq ";
    command += "--pid-file=";
    command += DNSMASQ_PID_FILE;
    command += " ";
    command += "--conf-file=";
    command += DNSMASQ_CONFIG_FILE;

    system(command.c_str());

    this->started = true;

    return true;
}


bool serviceDnsmasq::stop()
{
    return true;
}

} /* namespace app */
