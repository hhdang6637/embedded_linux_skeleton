/*
 * serviceOpenvpn.cpp
 *
 *  Created on: Aug 16, 2018
 *      Author: hhdang
 */

#include <unistd.h>

#include "serviceOpenvpn.h"

#define OPENVPN_PID_FILE    "/var/run/openvpn.pid"

namespace app
{

serviceOpenvpn::serviceOpenvpn()
{
    // TODO Auto-generated constructor stub

}

serviceOpenvpn::~serviceOpenvpn()
{
    // TODO Auto-generated destructor stub
}

std::string serviceOpenvpn::service_name()
{
    static std::string service_name("ntpd");
    return service_name;
}

serviceOpenvpn *serviceOpenvpn::s_instance = 0;

serviceOpenvpn* serviceOpenvpn::getInstance()
{
    if (s_instance == 0) {
        s_instance = new serviceOpenvpn();
    }

    return s_instance;
}

bool serviceOpenvpn::init()
{
    // for openvpn
    system("modprobe tun");

    return true;
}

bool serviceOpenvpn::start()
{
    std::string command;

    if (access("/data/openvpn/openvpn.conf", F_OK) == -1) {
        return false;
    }

    command = "/usr/sbin/openvpn --config /data/openvpn/openvpn.conf --daemon --writepid " OPENVPN_PID_FILE;
    system(command.c_str());

    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    // FIXME - hardcode ip and interface
    setenv("XTABLES_LIBDIR", "/usr/lib", 1);
    system("iptables -t nat -I POSTROUTING -o eth0 -s 192.168.255.0/24 -j MASQUERADE");

    return true;
}

} /* namespace app */
