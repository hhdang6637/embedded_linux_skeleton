#include <string>
#include <sstream>

#include <fcgiapp.h>
#include <syslog.h>

#include "utilities.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "rpcUnixClient.h"
#include "fcgi.h"
#include "openvpn_js.h"
#include "rpcMessageOpenvpn.h"

static inline std::string build_openvpn_rsp_json(std::string status, std::string message = "")
{
    std::ostringstream ss_json;

    ss_json << "{";
    ss_json << "\"status\": \"" << status << "\",";
    ss_json << "\"message\": \"" << message << "\"";
    ss_json << "}";

    return ss_json.str();
}

std::string json_handle_openvpn_cfg(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::string status      = "failed";

    // app::openvpnCfg_t openvpnCfg;

    if (method && (strcmp(method, "POST") == 0) && contentType)
    {
        // POST
        std::string data;

        if (get_post_data(request, data)) {
            try {

                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);
                POSTParser.AcceptSomeData(data.c_str(), data.size());

                std::string state;
                std::string port;

                state = POSTParser.GetField("state")->GetTextTypeContent();
                port = POSTParser.GetField("port_vpn")->GetTextTypeContent();

                status = "succeeded";

                return build_openvpn_rsp_json(status, "success");

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_openvpn_rsp_json(status, e.GetError().c_str());
            }

        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_openvpn_rsp_json(status, "Failed to get data from browser");
        }

    } else if (method && (strcmp(method, "GET") == 0)) {

        std::ostringstream ss_json;

        ss_json << "{\"json_openvpn_config\": [{";

        ss_json << "\"state\":";
        ss_json << "\"1\"";
        ss_json << ", ";

        ss_json << "\"port\":";
        ss_json << "\"1194\"";

        ss_json << "}]}";

        return ss_json.str();
    }

    return build_openvpn_rsp_json(status, "failed");
}
