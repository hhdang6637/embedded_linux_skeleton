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

                if(stoi(enable_ntp) == 1) // enable
                {
                    std::string ntp_server = POSTParser.GetFieldText("ntp_server");
                    std::string ntp_server1 = POSTParser.GetFieldText("ntp_server1");
                    std::string ntp_server2 = POSTParser.GetFieldText("ntp_server2");
                    std::string ntp_server3 = POSTParser.GetFieldText("ntp_server3");

                    memset(ntpCfg.ntp_server, 0, sizeof(ntpCfg.ntp_server));
                    memset(ntpCfg.ntp_server1, 0, sizeof(ntpCfg.ntp_server1));
                    memset(ntpCfg.ntp_server2, 0, sizeof(ntpCfg.ntp_server2));
                    memset(ntpCfg.ntp_server3, 0, sizeof(ntpCfg.ntp_server3));

                    strncpy(ntpCfg.ntp_server, ntp_server.c_str(), strlen(ntp_server.c_str()));
                    strncpy(ntpCfg.ntp_server1, ntp_server1.c_str(), strlen(ntp_server1.c_str()));
                    strncpy(ntpCfg.ntp_server2, ntp_server2.c_str(), strlen(ntp_server2.c_str()));
                    strncpy(ntpCfg.ntp_server3, ntp_server3.c_str(), strlen(ntp_server3.c_str()));

                    if (app::rpcMessageTime::rpcSetNtpCfg(*rpcClient, ntpCfg) != app::rpcMessageTimeResultType::SUCCESS) {
                        status = "failed";
                    }
                }
                else
                {
                    std::string date = POSTParser.GetFieldText("date");

                    std::string mytime = POSTParser.GetFieldText("time");

                    char date_time[17];
                    snprintf(date_time, sizeof(date_time), "%s %s", date.c_str(), mytime.c_str());
                    strptime(date_time, "%Y-%m-%d %H:%M", &sysTime);

                    if (app::rpcMessageTime::rpcSetSystemTime(*rpcClient, sysTime) != app::rpcMessageTimeResultType::SUCCESS) {
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
        ss_json << ((ntpCfg.state == 0) ? "0" : "1");
        ss_json << "\", ";

        ss_json << "\"ntp_server\": ";
        ss_json << "\"";
        ss_json << ntpCfg.ntp_server;
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
