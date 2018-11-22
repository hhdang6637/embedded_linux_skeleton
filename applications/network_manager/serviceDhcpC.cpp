/*
 * serviceDhcpC.cpp
 *
 *  Created on: Jul 27, 2018
 *      Author: hhdang
 */
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include "serviceDhcpC.h"

namespace app
{

serviceDhcpC::serviceDhcpC() : dhcpClientPid(-1), started(false)
{
    // TODO Auto-generated constructor stub

}

serviceDhcpC::~serviceDhcpC()
{
    // TODO Auto-generated destructor stub
}

serviceDhcpC *serviceDhcpC::s_instance = 0;

serviceDhcpC* serviceDhcpC::getInstance()
{
    if (s_instance == 0) {
        s_instance = new serviceDhcpC();
    }

    return s_instance;
}

std::string serviceDhcpC::service_name()
{
    static std::string service_name("udhcpc");
    return service_name;
}

bool serviceDhcpC::init()
{
    // nothing to init
    return true;
}

bool serviceDhcpC::start()
{
    if (this->started == true) {
        return true;
    }

    if (this->managedInterfaces.size() == 0) {
        syslog(LOG_ERR, "canot start udcpc with no interface");
        return false;
    }

    // fork to start cdhcpc as child proccess

    switch ((this->dhcpClientPid = fork())) {
    case -1:
        syslog(LOG_ERR, "canot fork to start udcpc");
        return false;
    case 0:
    {
        int fd = open("/dev/null", O_RDWR, 0);
        if (fd != -1) {
            (void) dup2(fd, STDIN_FILENO);
            (void) dup2(fd, STDOUT_FILENO);
            (void) dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO)
                (void) close(fd);
        }

        (void) chdir("/");

        std::vector<const char*> arg_v;
        arg_v.push_back("udhcpc");
        arg_v.push_back("-S"); // log to syslog

        arg_v.push_back("-i");

        for (auto &inf : this->managedInterfaces) {
            arg_v.push_back(inf.c_str());
        }

        arg_v.push_back(NULL);

        execv("/sbin/udhcpc", (char* const*)arg_v.data());
    }
        break;
    default:
        break;
    }

    syslog(LOG_NOTICE, "udhcpc was started, pid = %d", this->dhcpClientPid);

    this->started = true;

    return true;
}

bool serviceDhcpC::stop()
{
    return true;
}

void serviceDhcpC::addManagedInterfaces(std::string infName)
{
    this->managedInterfaces.push_back(infName);
}

} /* namespace app */
