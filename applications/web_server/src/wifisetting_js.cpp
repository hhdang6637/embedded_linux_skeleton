/*
 * wifisetting_js.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include <string>
#include <sstream>

#include <fcgiapp.h>
#include <syslog.h>

#include "wifisetting_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "rpcUnixClient.h"
#include "fcgi.h"


static std::string ssid, preshared_key;
static int security_type, access_point;

static inline std::string build_wifisetting_rsp_json(std::string status, std::string message = "") {
    std::ostringstream ss_json;
    ss_json << "{";
    ss_json << "\"status\": \"" << status <<"\",";
    ss_json << "\"message\": \""<< message <<"\"";
    ss_json << "}";

    return ss_json.str();
}

static inline bool validateSsid(const char* _ssid)
{
    const char* specialKeyAllow = " .-_";
    char *c = NULL;
    int i = 0;
    int lengthSsid = 0;

    if(_ssid == NULL)
        return false;

    lengthSsid = strlen(_ssid);

    if(lengthSsid > 32){
        return false;
    }

    for(; i < lengthSsid; i++)
    {
        c = (char*) strchr(specialKeyAllow, _ssid[i]);

        if(c == NULL)
        {
            //in range [0-9]
            if(_ssid[i] >= '0' && _ssid[i] <= '9')
                continue;

            //in range [A-F]
            if(_ssid[i] >= 'A' && _ssid[i] <= 'F')
                continue;

            //in range[a-f]
            if(_ssid[i] >= 'a' && _ssid[i] <= 'f')
                continue;

            return false;
        }
    }

    return true;
}

static inline bool validatePresharedKey(const char* pwd)
{
    int i = 0;
    int lengthPwd = 0;

    if(pwd == NULL)
        return false;
    lengthPwd = strlen(pwd);

    if(lengthPwd < 8 || lengthPwd > 64)
        return false;

    for(; i < lengthPwd; i++)
    {
        //in range [0-9]
        if(pwd[i] >= '0' && pwd[i] <= '9')
            continue;

        if(lengthPwd == 64)
        {
            //in range [A-F]
            if(pwd[i] >= 'A' && pwd[i] <= 'F')
                continue;

            //in range[a-f]
            if(pwd[i] >= 'a' && pwd[i] <= 'f')
                continue;
        }
        else
        {
            //in range [A-Z]
            if(pwd[i] >= 'A' && pwd[i] <= 'Z')
                continue;

            //in range[a-z]
            if(pwd[i] >= 'a' && pwd[i] <= 'z')
                continue;
        }
        return false;
    }
    return true;
}

std::string json_handle_wifisetting(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::ostringstream ss_json;
    std::string status;
    status.assign("failed");

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (get_post_data(request, data))
        {
            try
            {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                preshared_key = POSTParser.GetField("preshared_key")->GetTextTypeContent();
                ssid = POSTParser.GetField("ssid")->GetTextTypeContent();
                access_point = atoi(POSTParser.GetField("access_point")->GetTextTypeContent().c_str());
                security_type = atoi(POSTParser.GetField("security_type")->GetTextTypeContent().c_str());

                printf("ssid: %s\n preshared_key: %s\n access_point: %d\n security_type:%d\n", ssid.c_str(), preshared_key.c_str(), access_point, security_type);

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_wifisetting_rsp_json(status, "Failed to get data from browser");
            }
        }
    }
    status.assign("succeeded");
    return build_wifisetting_rsp_json(status);
}
