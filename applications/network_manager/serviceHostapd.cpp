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
    memset(this->msgData.presharedKey, 0, sizeof(this->msgData.presharedKey));
    strncpy(this->msgData.presharedKey, "somepassword", strlen("somepassword"));
    memset(this->msgData.ssid, 0 , sizeof(this->msgData.ssid));
    strncpy(this->msgData.ssid, "somename", strlen("somename"));
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

    initFromFile();

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
                            "ssid="<<this->msgData.ssid<<"\n"
                            "rsn_pairwise=CCMP\n";

        if(msgData.securityType == 1)
        {
            hostapd_conf_file <<
                        "auth_algs=1\n"
                        "wpa=2\n"
                        "wpa_key_mgmt=WPA-PSK\n"
                        "wpa_passphrase="<<this->msgData.presharedKey<<"\n";
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

    if (this->msgData.accessPoint == 1) {
        if (system(command.c_str()) != -1) {
            this->started = true;
            syslog(LOG_NOTICE, "Hostapd started...\n");
            return true;
        }
    } else {
        this->started = false;
        syslog(LOG_NOTICE, "Hostapd NOT started...\n");
        return true;
    }

    return false;
}

bool serviceHostapd::stop()
{
    if (this->started == true) {
        if (system("kill `pidof hostapd`") != -1) {
            sleep(2);

            if (system("pidof hostapd") > 0) {
                if (system("kill -9 `pidof hostapd`") != -1) {
                    this->started = false;
                    return true;
                }
            } else {
                this->started = false;
                return true;
            }
        }
    }

    return false;
}

bool serviceHostapd::restart()
{
    if (this->stop() == true) {
        if (this->init() == true) {
            if (this->start() == true) {
                return true;
            }
        }
    }

    return false;
}

bool serviceHostapd::writeToFile()
{
    app::ini networkConf;
    std::string value;

    value = this->msgData.ssid;
    networkConf.set_string("wifi_setting", "ssid", value);

    value = this->msgData.presharedKey;
    networkConf.set_string("wifi_setting", "presharedkey", value);

    networkConf.set_uint16("wifi_setting", "securitytype", this->msgData.securityType);
    networkConf.set_uint16("wifi_setting", "accesspoint", this->msgData.accessPoint);

    return networkConf.writeToFile("/data/network.conf");
}

bool serviceHostapd::initFromFile()
{
    app::ini networkConf;
    std::string value;
    uint16_t uint16_value;

    if (networkConf.loadFromFile("/data/network.conf")) {

        if (networkConf.get_string("wifi_setting", "ssid", value)) {

            memset(this->msgData.ssid, 0, sizeof(this->msgData.ssid));
            strncpy(this->msgData.ssid, value.c_str(), value.length());

            if (networkConf.get_string("wifi_setting", "presharedkey", value)) {
                memset(this->msgData.presharedKey, 0, sizeof(this->msgData.presharedKey));
                strncpy(this->msgData.presharedKey, value.c_str(), value.length());
            }

            if (networkConf.get_uint16("wifi_setting", "securitytype", uint16_value)) {
                this->msgData.securityType = uint16_value;
            }

            if (networkConf.get_uint16("wifi_setting", "accesspoint", uint16_value)) {
                this->msgData.accessPoint = uint16_value;
            }
        }

    } else {
        syslog(LOG_NOTICE, "cannot load user config from /data/users.conf, use default config");
        return false;
    }

    return true;
}

void serviceHostapd::setWifiSettingData(const app::rpcMessageWifiSettingData_t msg)
{
    this->msgData = msg;

    writeToFile();

    syslog(LOG_NOTICE, "setWifiSettingData: %s %s %u %u\n", this->msgData.presharedKey, this->msgData.ssid,
           this->msgData.accessPoint, this->msgData.securityType);
}

app::rpcMessageWifiSettingData_t serviceHostapd::getWifiSettingData() const
{
   return this->msgData;
}

static inline rpcMessageWifiSettingResultType validateSsid(const char* _ssid)
{
    syslog(LOG_NOTICE, "SSID: %s", _ssid);
    const char* specialKeyAllow = " .-_";
    char *c = NULL;
    int i = 0;
    int lengthSsid = 0;

    if (_ssid == NULL) {
        return app::rpcMessageWifiSettingResultType::SSID_IS_NULL;
    }

    lengthSsid = strlen(_ssid);

    if (lengthSsid == 0 || lengthSsid > SSID_LENGTH) {
        return app::rpcMessageWifiSettingResultType::SSID_LENGTH_INVALID;
    }

    for (; i < lengthSsid; i++) {

        c = (char*) strchr(specialKeyAllow, _ssid[i]);

        if (c == NULL) {
            //in range [0-9]
            if (_ssid[i] >= '0' && _ssid[i] <= '9') {
                continue;
            }

            //in range [A-Z]
            if (_ssid[i] >= 'A' && _ssid[i] <= 'Z') {
                continue;
            }

            //in range[a-z]
            if (_ssid[i] >= 'a' && _ssid[i] <= 'z') {
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

    if (pwd == NULL) {
        return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_IS_NULL;
    }

    lengthPwd = strlen(pwd);

    if (lengthPwd < 8 || lengthPwd > PRESHARED_KEY_LENGTH) {
        return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_LENGTH_INVALID;
    }

    for (i = 0; i < lengthPwd; i++) {
        //in range [0-9]
        if (pwd[i] >= '0' && pwd[i] <= '9') {
            continue;
        }

        if (lengthPwd == 64) {
            //in range [A-F]
            if (pwd[i] >= 'A' && pwd[i] <= 'F') {
                continue;
            }

            //in range[a-f]
            if (pwd[i] >= 'a' && pwd[i] <= 'f') {
                continue;
            }

        } else {
            //in range [A-Z]
            if (pwd[i] >= 'A' && pwd[i] <= 'Z') {
                continue;
            }

            //in range[a-z]
            if (pwd[i] >= 'a' && pwd[i] <= 'z') {
                continue;
            }
        }

        return app::rpcMessageWifiSettingResultType::PRESHAREDKEY_CHARACTER_INVALID;
    }

    return app::rpcMessageWifiSettingResultType::SUCCEEDED;
}

app::rpcMessageWifiSettingResultType serviceHostapd::validateMsgConfig(
        const app::rpcMessageWifiSettingData_t *msgData) const
{
    rpcMessageWifiSettingResultType resultValid;

    resultValid = validateSsid(msgData->ssid);
    if (resultValid != SUCCEEDED)
        return resultValid;

    if (msgData->securityType == 0)
        return resultValid;

    resultValid = validatePresharedKey(msgData->presharedKey);

    return resultValid;
}

} /* namespace app */
