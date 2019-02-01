#include <string>
#include <sstream>

#include <fcgiapp.h>
#include <syslog.h>
#include <time.h>

#include "utilities.h"
#include "wifisetting_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "rpcUnixClient.h"
#include "fcgi.h"
#include "rpcMessageTime.h"

static inline std::string build_time_ntp_rsp_json(std::string status, std::string message = "")
{
    std::ostringstream ss_json;

    ss_json << "{";
    ss_json << "\"status\": \"" << status << "\",";
    ss_json << "\"message\": \"" << message << "\"";
    ss_json << "}";

    return ss_json.str();
}

std::string json_handle_time_ntp(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::ntpConfig_t ntpCfg = app::ntpConfig_t();
    tm sysTime;

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;
        std::string status = "failed";

        if (get_post_data(request, data)) {
            try {
                MPFD::Parser POSTParser;
                app::rpcMessageTimeResultType result;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                ntpCfg.state = POSTParser.GetFieldText("enable_ntp") == "enable" ? app::stateType::ENABLE : app::stateType::DISABLE;

                if(ntpCfg.state == app::stateType::ENABLE)
                {
                    string_copy(ntpCfg.ntp_server0, POSTParser.GetFieldText("ntp_server0"), sizeof(ntpCfg.ntp_server0));
                    string_copy(ntpCfg.ntp_server1, POSTParser.GetFieldText("ntp_server1"), sizeof(ntpCfg.ntp_server1));
                    string_copy(ntpCfg.ntp_server2, POSTParser.GetFieldText("ntp_server2"), sizeof(ntpCfg.ntp_server2));
                    string_copy(ntpCfg.ntp_server3, POSTParser.GetFieldText("ntp_server3"), sizeof(ntpCfg.ntp_server3));

                    result = app::rpcMessageTime::rpcSetNtpCfg(*rpcClient, ntpCfg);
                }
                else
                {
                    char date_time[17];
                    snprintf(date_time, sizeof(date_time), "%s %s", POSTParser.GetFieldText("date").c_str(), POSTParser.GetFieldText("time").c_str());
                    strptime(date_time, "%Y-%m-%d %H:%M", &sysTime);

                    result = app::rpcMessageTime::rpcSetSystemTime(*rpcClient, sysTime);
                }

                if (result == app::rpcMessageTimeResultType::SUCCESS) {
                    status = "succeeded";
                }

                return build_time_ntp_rsp_json(status, app::rpcMessageTime::timeMsgResult2Str(result));

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_time_ntp_rsp_json("failed", e.GetError().c_str());
            }

        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_time_ntp_rsp_json(status, "Failed to get data from browser");
        }

    } else if (method && (strcmp(method, "GET") == 0)) {

        memset(&ntpCfg, 0, sizeof(ntpCfg));
        memset(&sysTime, 0, sizeof(sysTime));

        if (app::rpcMessageTime::rpcGetNtpCfg(*rpcClient, ntpCfg) != app::rpcMessageTimeResultType::SUCCESS)
            return build_time_ntp_rsp_json("failed", "RPC rpcGetNtpCfg error");

        if (app::rpcMessageTime::rpcGetSystemTime(*rpcClient, sysTime) != app::rpcMessageTimeResultType::SUCCESS)
            return build_time_ntp_rsp_json("failed", "RPC rpcGetSystemTime error");

        char date[11];
        char _time[6];
        strftime(date, sizeof(date), "%Y-%m-%d", &sysTime);
        strftime(_time, sizeof(_time), "%H:%M", &sysTime);

        std::ostringstream ss_json;

        ss_json << "{\"json_time_ntp\": {";

        ss_json << "\"enable_ntp\": ";
        ss_json << "\"";
        ss_json << ((ntpCfg.state == app::stateType::ENABLE) ? "enable" : "disable");
        ss_json << "\", ";

        ss_json << "\"ntp_server0\": ";
        ss_json << "\"";
        ss_json << ntpCfg.ntp_server0;
        ss_json << "\", ";

        ss_json << "\"ntp_server1\": ";
        ss_json << "\"";
        ss_json << ntpCfg.ntp_server1;
        ss_json << "\", ";

        ss_json << "\"ntp_server2\": ";
        ss_json << "\"";
        ss_json << ntpCfg.ntp_server2;
        ss_json << "\", ";

        ss_json << "\"ntp_server3\": ";
        ss_json << "\"";
        ss_json << ntpCfg.ntp_server3;
        ss_json << "\", ";

        ss_json << "\"date\": ";
        ss_json << "\"";
        ss_json << date;
        ss_json << "\", ";

        ss_json << "\"time\": ";
        ss_json << "\"";
        ss_json << _time;
        ss_json << "\"";

        ss_json << "}}";

        return ss_json.str();
    }

    return build_time_ntp_rsp_json("succeeded", "succeeded");
}
