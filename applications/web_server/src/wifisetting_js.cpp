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

#include "utilities.h"
#include "wifisetting_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "rpcUnixClient.h"
#include "fcgi.h"
#include "rpcMessageWifiSetting.h"

static inline std::string build_wifisetting_rsp_json(std::string status, std::string message = "")
{

    std::ostringstream ss_json;

    ss_json << "{";
    ss_json << "\"status\": \"" << status << "\",";
    ss_json << "\"message\": \"" << message << "\"";
    ss_json << "}";

    return ss_json.str();
}

app::rpcMessageWifiSettingResultType do_set_wifisetting(app::rpcMessageWifiSettingData_t &msgData)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageWifiSetting msgWifiSetting;

    msgWifiSetting.setWifiSettingMsgData(msgData);
    msgWifiSetting.setMsgAction(app::rpcMessageWifiSettingActionType::EDIT_WIFI_SETTING);

    if (rpcClient->doRpc(&msgWifiSetting) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return app::rpcMessageWifiSettingResultType::UNKNOWN_ERROR;
    }

    return msgWifiSetting.getMsgResult();
}

bool do_get_wifisetting(app::rpcMessageWifiSetting &msgWifiSetting)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();

    msgWifiSetting.setMsgAction(app::rpcMessageWifiSettingActionType::GET_WIFI_SETTING);

    if (rpcClient->doRpc(&msgWifiSetting) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

std::string json_handle_wifisetting(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::string status      = "failed";

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (get_post_data(request, data)) {
            try {
                app::rpcMessageWifiSettingData_t msgData = app::rpcMessageWifiSettingData_t();
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                ::string_copy(msgData.presharedKey, POSTParser.GetFieldText("preshared_key"), sizeof(msgData.presharedKey));

                ::string_copy(msgData.ssid, POSTParser.GetFieldText("ssid"), sizeof(msgData.ssid));

                msgData.accessPoint = std::stoi(POSTParser.GetField("access_point")->GetTextTypeContent());
                msgData.securityType = std::stoi(POSTParser.GetField("security_type")->GetTextTypeContent());

                auto result = do_set_wifisetting(msgData);
                if (result == app::rpcMessageWifiSettingResultType::SUCCEEDED) {
                    status = "succeeded";
                }

                return build_wifisetting_rsp_json(status, wifiMsgResult2Str(result));

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_wifisetting_rsp_json(status, e.GetError().c_str());
            }

        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_wifisetting_rsp_json(status, "Failed to get data from browser");
        }

    } else if (method && (strcmp(method, "GET") == 0)) {
        app::rpcMessageWifiSetting msgWifiSetting;
        if (do_get_wifisetting(msgWifiSetting) == false) {
            return build_wifisetting_rsp_json(status, "RPC error");
        }

        std::ostringstream ss_json;

        ss_json << "{\"json_wifi_setting\": {";

        ss_json << "\"preshared_key\": ";
        ss_json << "\"";
        ss_json << msgWifiSetting.getWifiSettingMsgData().presharedKey;
        ss_json << "\", ";

        ss_json << "\"ssid\": ";
        ss_json << "\"";
        ss_json << msgWifiSetting.getWifiSettingMsgData().ssid;
        ss_json << "\", ";

        ss_json << "\"access_point\": ";
        ss_json << "\"";
        ss_json << msgWifiSetting.getWifiSettingMsgData().accessPoint;
        ss_json << "\", ";

        ss_json << "\"security_type\": ";
        ss_json << "\"";
        ss_json << msgWifiSetting.getWifiSettingMsgData().securityType;
        ss_json << "\"";

        ss_json << "}}";

        return ss_json.str();
    }

    return build_wifisetting_rsp_json(status, wifiMsgResult2Str(app::rpcMessageWifiSettingResultType::UNKNOWN_ERROR));
}
