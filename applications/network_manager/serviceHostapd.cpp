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
    this->msgData.presharedKey = "somepassword";
    this->msgData.ssid = "somename";
    this->msgData.securityType = 1;
    this->msgData.accessPoint = 1;
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
                            "ssid="<< this->msgData.ssid <<"\n"
                            "rsn_pairwise=CCMP\n";

        if(msgData.securityType == 1) {
            hostapd_conf_file <<
                                "auth_algs=1\n"
                                "wpa=2\n"
                                "wpa_key_mgmt=WPA-PSK\n"
                                "wpa_passphrase="<< this->msgData.presharedKey <<"\n";
        }
        else if(msgData.securityType == 0) {
            hostapd_conf_file <<
                                "auth_algs=0\n";
        }

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

    if(this->msgData.accessPoint == 1)
    {
        if(system(command.c_str()) != -1)
        {
            this->started = true;
            return true;
        }
    }
    else
    {
        this->started = false;
        return true;
    }

    return false;
}

bool serviceHostapd::stop()
{
    if(this->started == true)
    {
        if(system("kill `pidof hostapd`") != -1)
        {
            sleep(2);

            if( system("pidof hostapd") > 0)
            {
                if(system("kill -9 `pidof hostapd`") != -1)
                {
                    this->started =  false;
                    return true;
                }
            }
            else
            {
                this->started =  false;
                return true;
            }
        }
    }
    return false;
}

void serviceHostapd::setWifiSettingData(const app::rpcMessageWifiSettingData_t msg)
{
    this->msgData = msg;
}

app::rpcMessageWifiSettingData_t serviceHostapd::getWifiSettingData() const
{
   return this->msgData;
}

bool serviceHostapd::writeToFile()
{
    app::ini serviceHostapdConf;
    char sect[256];

    snprintf(sect, sizeof(sect), "service_hostapd");

    serviceHostapdConf.set_string(sect, "presharedKey", this->msgData.presharedKey);

    serviceHostapdConf.set_string(sect, "ssid", this->msgData.ssid);

    serviceHostapdConf.set_uint16(sect, "accessPoint", this->msgData.accessPoint);

    serviceHostapdConf.set_uint16(sect, "securityType", this->msgData.securityType);

    return serviceHostapdConf.writeToFile("/data/service_hostapd.conf");
}

bool serviceHostapd::initFromFile()
{
    app::ini serviceHostapdConf;

    if (serviceHostapdConf.loadFromFile("/data/service_hostapd.conf")) {

        char sect[256];
        std::string value;

        snprintf(sect, sizeof(sect), "service_hostapd");
        syslog(LOG_NOTICE, "found service_hostapd from /data/service_hostapd.conf");


        if (serviceHostapdConf.get_string(sect, "presharedKey", this->msgData.presharedKey)) {
            return false;
        }

        if (serviceHostapdConf.get_string(sect, "ssid", this->msgData.ssid)) {
            return false;
        }

        if (serviceHostapdConf.get_uint16(sect, "accessPoint", this->msgData.accessPoint)) {
            return false;
        }

        if (serviceHostapdConf.get_uint16(sect, "securityType", this->msgData.securityType)) {
            return false;
        }

    } else {
        syslog(LOG_NOTICE, "cannot load user config from /data/users.conf, use default users");
        return false;
    }

    return true;
}

static inline rpcMessageWifiSettingResultType validateSsid(const char* _ssid)
{
    const char* specialKeyAllow = " .-_";
    char *c = NULL;
    int i = 0;
    int lengthSsid = 0;

    if(_ssid == NULL) {
        return app::rpcMessageWifiSettingResultType::SSID_IS_NULL;
    }

    lengthSsid = strlen(_ssid);

    if(lengthSsid > 32){
        return app::rpcMessageWifiSettingResultType::SSID_LENGTH_INVALID;
    }

    for(; i < lengthSsid; i++) {

        c = (char*) strchr(specialKeyAllow, _ssid[i]);

        if(c == NULL) {
            //in range [0-9]
            if(_ssid[i] >= '0' && _ssid[i] <= '9') {
                continue;
            }

            //in range [A-F]
            if(_ssid[i] >= 'A' && _ssid[i] <= 'F') {
                continue;
            }

            //in range[a-f]
            if(_ssid[i] >= 'a' && _ssid[i] <= 'f') {
                continue;
            }

            return app::rpcMessageWifiSettingResultType::SSID_CHARACTER_INVALID;
        }
    }

    return app::rpcMessageWifiSettingResultType::SUCCEEDED;
}

static inline rpcMessageWifiSettingResultType validatePresharedKey(const char* pwd)
{
    int i = 0;
    int lengthPwd = 0;

    if(pwd == NULL) {
        return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_IS_NULL;
    }

    lengthPwd = strlen(pwd);

    if(lengthPwd < 8 || lengthPwd > 64) {
        return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_LENGTH_INVALID;
    }

    for(i = 0; i < lengthPwd; i++) {
        //in range [0-9]
        if(pwd[i] >= '0' && pwd[i] <= '9') {
            continue;
        }

        if(lengthPwd == 64) {
            //in range [A-F]
            if(pwd[i] >= 'A' && pwd[i] <= 'F') {
                continue;
            }

            //in range[a-f]
            if(pwd[i] >= 'a' && pwd[i] <= 'f') {
                continue;
            }

        } else {
            //in range [A-Z]
            if(pwd[i] >= 'A' && pwd[i] <= 'Z') {
                continue;
            }

            //in range[a-z]
            if(pwd[i] >= 'a' && pwd[i] <= 'z') {
                continue;
            }
        }

        return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_CHARACTER_INVALID;
    }

    return app::rpcMessageWifiSettingResultType::SUCCEEDED;
}

app::rpcMessageWifiSettingResultType serviceHostapd::validateMsgConfig(const app::rpcMessageWifiSettingData_t msgData) const
{
    rpcMessageWifiSettingResultType resultValid;
    resultValid = validatePresharedKey((char*)(&msgData.presharedKey));
    
    if(resultValid != SUCCEEDED)
        return resultValid;

    resultValid = validateSsid((char*)(&msgData.ssid));

    return resultValid;
}

} /* namespace app */
