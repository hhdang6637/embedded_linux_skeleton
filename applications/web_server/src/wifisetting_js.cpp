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


static inline std::string build_wifisetting_rsp_json(std::string status, std::string message = "") {
    std::ostringstream ss_json;
    ss_json << "{";
    ss_json << "\"status\": \"" << status <<"\",";
    ss_json << "\"message\": \""<< message <<"\"";
    ss_json << "}";

    return ss_json.str();
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
            std::string preshared_key, ssid, access_point;

            try
            {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                preshared_key = POSTParser.GetField("preshared_key")->GetTextTypeContent();
                ssid = POSTParser.GetField("ssid")->GetTextTypeContent();
                access_point = POSTParser.GetField("access_point")->GetTextTypeContent();

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_wifisetting_rsp_json(status, "Failed to get data from browser");
            }
        }
    }
    status.assign("succeeded");
    return build_wifisetting_rsp_json(status);
}
