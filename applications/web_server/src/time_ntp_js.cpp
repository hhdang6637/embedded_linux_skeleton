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

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (get_post_data(request, data)) {
            try {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                std::string enable_ntp = POSTParser.GetField("enable_ntp")->GetTextTypeContent();
                syslog(LOG_INFO, "json_handle_time_ntp: enable_ntp: %s\n", enable_ntp.c_str());
                if(stoi(enable_ntp) == 1) // enable
                {
                    std::string ntp_server = POSTParser.GetField("ntp_server")->GetTextTypeContent();
                    syslog(LOG_INFO, "json_handle_time_ntp: ntp_server: %s\n", ntp_server.c_str());
                }
                else
                {
                    struct tm date_time;
                    std::string date = POSTParser.GetField("date")->GetTextTypeContent();
                    syslog(LOG_INFO, "json_handle_time_ntp: date: %s\n", date.c_str());
                    strptime(date.c_str(), "%Y-%m-%d", &date_time);

                    std::string time = POSTParser.GetField("time")->GetTextTypeContent();
                    syslog(LOG_INFO,"json_handle_time_ntp: time: %s\n", time.c_str());
                    strptime(time.c_str(), "%H:%M", &date_time);

                    syslog(LOG_INFO, "json_handle_time_ntp: time2: H=%d M=%d\n", date_time.tm_hour, date_time.tm_min);
                    syslog(LOG_INFO, "json_handle_time_ntp: date2: d=%d m=%d y=%d\n", date_time.tm_mday, date_time.tm_mon, date_time.tm_year);
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

        std::ostringstream ss_json;

        ss_json << "{\"json_time_ntp\": {";

        ss_json << "\"enable_ntp\": ";
        ss_json << "\"";
        ss_json << "0";
        ss_json << "\", ";

        ss_json << "\"ntp_server\": ";
        ss_json << "\"";
        ss_json << "";
        ss_json << "\", ";

        ss_json << "\"date\": ";
        ss_json << "\"";
        ss_json << "2019-01-22";
        ss_json << "\", ";

        ss_json << "\"time\": ";
        ss_json << "\"";
        ss_json << "12:22";
        ss_json << "\"";

        ss_json << "}}";

        return ss_json.str();
    }

    return build_time_ntp_rsp_json("succeeded", "succeeded");
}