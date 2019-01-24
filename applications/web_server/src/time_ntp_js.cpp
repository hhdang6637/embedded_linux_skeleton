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
    std::string status      = "failed";
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageTime rpcTime;
    app::ntpConfig_t ntpCfg;
    tm sysTime;

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (get_post_data(request, data)) {
            try {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                std::string enable_ntp = POSTParser.GetFieldText("enable_ntp");
                ntpCfg.state = std::atoi(enable_ntp.c_str());
                syslog(LOG_INFO, "json_handle_time_ntp: enable_ntp: %s\n", enable_ntp.c_str());

                if(stoi(enable_ntp) == 1) // enable
                {
                    std::string ntp_server = POSTParser.GetFieldText("ntp_server");
                    memset(ntpCfg.ntp_server, 0, sizeof(ntpCfg.ntp_server));
                    strncpy(ntpCfg.ntp_server, ntp_server.c_str(), strlen(ntp_server.c_str()));
                    syslog(LOG_INFO, "json_handle_time_ntp: len of ntp_server: %d\n", strlen(ntp_server.c_str()));
                    syslog(LOG_INFO, "json_handle_time_ntp: ntp_server: %s\n", ntp_server.c_str());
                    if (rpcTime.rpcSetNtpCfg(*rpcClient, ntpCfg) != app::rpcMessageTimeResultType::SUCCESS) {
                        status = "failed";
                    }
                }
                else
                {
                    std::string date = POSTParser.GetFieldText("date");
                    syslog(LOG_INFO, "json_handle_time_ntp: date: %s\n", date.c_str());

                    std::string mytime = POSTParser.GetFieldText("time");
                    syslog(LOG_INFO,"json_handle_time_ntp: time: %s\n", mytime.c_str());

                    char date_time[17];
                    snprintf(date_time, sizeof(date_time), "%s %s", date.c_str(), mytime.c_str());
                    strptime(date_time, "%Y-%m-%d %H:%M", &sysTime);

                    syslog(LOG_INFO, "json_handle_time_ntp: time2: H=%d M=%d\n", sysTime.tm_hour, sysTime.tm_min);
                    syslog(LOG_INFO, "json_handle_time_ntp: date2: d=%d m=%d y=%d\n", sysTime.tm_mday, sysTime.tm_mon, sysTime.tm_year);

                    if (rpcTime.rpcSetNtpCfg(*rpcClient, ntpCfg) != app::rpcMessageTimeResultType::SUCCESS) {
                        status = "failed";
                    }
                    if(rpcTime.rpcSetSystemTime(*rpcClient,sysTime) != app::rpcMessageTimeResultType::SUCCESS){
                        status = "failed";
                    }
                }

                return build_time_ntp_rsp_json("succeeded", "succeeded");

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_time_ntp_rsp_json(status, e.GetError().c_str());
            }

        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_time_ntp_rsp_json(status, "Failed to get data from browser");
        }

    } else if (method && (strcmp(method, "GET") == 0)) {

        app::rpcMessageTime rpcTime;
        auto resultRpcGetNtpCfg = rpcTime.rpcGetNtpCfg(*rpcClient, ntpCfg);
        if (resultRpcGetNtpCfg != app::rpcMessageTimeResultType::SUCCESS)
            return build_time_ntp_rsp_json("failed", "RPC rpcGetNtpCfg error");

        auto resultRpcGetSystemTime = rpcTime.rpcGetSystemTime(*rpcClient, sysTime);
        if(resultRpcGetSystemTime != app::rpcMessageTimeResultType::SUCCESS)
            return build_time_ntp_rsp_json("failed", "RPC rpcGetSystemTime error");

        std::ostringstream ss_json;

        ss_json << "{\"json_time_ntp\": {";

        ss_json << "\"enable_ntp\": ";
        ss_json << "\"";
        ss_json << ((ntpCfg.state == 0) ? "0" : "1");
        ss_json << "\", ";

        if(ntpCfg.state == 1)
        {
            ss_json << "\"ntp_server\": ";
            ss_json << "\"";
            ss_json << ntpCfg.ntp_server;
            ss_json << "\", ";

            ss_json << "\"date\": ";
            ss_json << "\"";
            ss_json << "";
            ss_json << "\", ";

            ss_json << "\"time\": ";
            ss_json << "\"";
            ss_json << "";
            ss_json << "\"";
        }
        else
        {
            ss_json << "\"ntp_server\": ";
            ss_json << "\"";
            ss_json << "";
            ss_json << "\", ";

            char date[11];
            strftime(date, sizeof(date), "%Y-%m-%d", &sysTime);

            ss_json << "\"date\": ";
            ss_json << "\"";
            ss_json << date;
            ss_json << "\", ";

            char _time[6];
            strftime(_time, sizeof(_time), "%H:%M", &sysTime);

            ss_json << "\"time\": ";
            ss_json << "\"";
            ss_json << _time;
            ss_json << "\"";
        }

        ss_json << "}}";

        return ss_json.str();
    }

    return build_time_ntp_rsp_json("succeeded", "succeeded");
}