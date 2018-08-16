/*
 * serviceOpenvpn.cpp
 *
 *  Created on: Aug 16, 2018
 *      Author: hhdang
 */

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
    command = "/usr/sbin/openvpn --config /data/openvpn/openvpn.conf --daemon --writepid " OPENVPN_PID_FILE;

    system(command.c_str());

    return true;
}

} /* namespace app */
