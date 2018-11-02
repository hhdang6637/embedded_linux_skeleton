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

std::string json_handle_wifisetting(FCGX_Request *request)
{
    const char *method = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::ostringstream ss_json;
    std::string status;
    status.assign("failed");
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageWifiSetting msgWifiSetting;

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (get_post_data(request, data)) {
            try {
                app::rpcMessageWifiSettingData_t msgData;
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());
                memset(msgData.presharedKey, 0, sizeof(msgData.presharedKey));
                memset(msgData.ssid, 0, sizeof(msgData.ssid));
                strncpy(msgData.presharedKey, POSTParser.GetField("preshared_key")->GetTextTypeContent().c_str(),
                        POSTParser.GetField("preshared_key")->GetTextTypeContent().length());
                strncpy(msgData.ssid, POSTParser.GetField("ssid")->GetTextTypeContent().c_str(),
                        POSTParser.GetField("ssid")->GetTextTypeContent().length());
                msgData.accessPoint = atoi(POSTParser.GetField("access_point")->GetTextTypeContent().c_str());
                msgData.securityType = atoi(POSTParser.GetField("security_type")->GetTextTypeContent().c_str());

                msgWifiSetting.setWifiSettingMsgData(msgData);
                msgWifiSetting.setMsgAction(app::rpcMessageWifiSettingActionType::EDIT_WIFI_SETTING);

                if (rpcClient->doRpc(&msgWifiSetting) == false) {
                    syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
                    return build_wifisetting_rsp_json(status, "Failed to get data from Network");
                }

                if (msgWifiSetting.getMsgResult() == app::rpcMessageWifiSettingResultType::SUCCEEDED) {
                    status.assign("succeeded");
                    return build_wifisetting_rsp_json(status, msgWifiSetting.wifiMsgResult2Str());
                } else {
                    return build_wifisetting_rsp_json(status, msgWifiSetting.wifiMsgResult2Str());
                }

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_wifisetting_rsp_json(status, "Failed to get data from browser");
            }
        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_wifisetting_rsp_json(status, "Failed to get data from browser");
        }
    } else if (method && (strcmp(method, "GET") == 0)) {
        msgWifiSetting.setMsgAction(app::rpcMessageWifiSettingActionType::GET_WIFI_SETTING);
        if (rpcClient->doRpc(&msgWifiSetting) == false) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return build_wifisetting_rsp_json(status, "Failed to get data from Network");
        }

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

    msgWifiSetting.setMsgResult(app::rpcMessageWifiSettingResultType::UNKNOWN_ERROR);
    return build_wifisetting_rsp_json(status, msgWifiSetting.wifiMsgResult2Str());
}
