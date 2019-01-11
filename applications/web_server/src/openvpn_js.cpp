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

app::openvpnCfgServer_t openvpnCfgServer;
app::openvpnCfgClient_t openvpnCfgClient;

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

    if (method && (strcmp(method, "POST") == 0) && contentType)
    {
        // POST
        std::string data;

        if (get_post_data(request, data)) {
            try {

                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                openvpnCfgServer.openvpnCfg.state = (int16_t) std::stoi(POSTParser.GetField("state")->GetTextTypeContent());

                std::string portStr = POSTParser.GetField("port")->GetTextTypeContent();
                strncpy(openvpnCfgServer.openvpnCfg.port, portStr.c_str(), portStr.length());
                strncpy(openvpnCfgClient.openvpnCfg.port, portStr.c_str(), portStr.length());

                printf("openvpnCfgServer.openvpnCfg.state: %d\n", openvpnCfgServer.openvpnCfg.state);
                printf("openvpnCfgClient.openvpnCfg.port: %s\n", openvpnCfgClient.openvpnCfg.port);

                return build_openvpn_rsp_json(status, "success");

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_openvpn_rsp_json(status, e.GetError().c_str());
            }

        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_openvpn_rsp_json(status, "Failed to get data from browser");
        }

    }
    else if (method && (strcmp(method, "GET") == 0))
    {
        std::ostringstream ss_json;

        ss_json << "{\"json_openvpn_config\": {";

        ss_json << "\"state\": ";
        ss_json << "\"";
        ss_json << "1";
        ss_json << "\", ";

        ss_json << "\"port\": ";
        ss_json << "\"";
        ss_json << "1194";
        ss_json << "\"";

        ss_json << "}}";

        return ss_json.str();
    }

    return build_openvpn_rsp_json(status, "failed");
}

std::string json_handle_openvpn_cfg_server(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::string status      = "failed";

    if (method && (strcmp(method, "POST") == 0) && contentType)
    {
        // POST
        std::string data;

        if (get_post_data(request, data)) {
            try {
                /*
                Handle request Re-Gen cert
                */
                return build_openvpn_rsp_json(status, "success");

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_openvpn_rsp_json(status, e.GetError().c_str());
            }

        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_openvpn_rsp_json(status, "Failed to get data from browser");
        }

    }
    else if (method && (strcmp(method, "GET") == 0))
    {
        std::ostringstream ss_json;

        ss_json << "{\"json_openvpn_config_server\": {";

        ss_json << "\"caCrtName\": ";
        ss_json << "\"";
        ss_json << "ca.crt";
        ss_json << "\", ";

        ss_json << "\"caEndDate\": ";
        ss_json << "\"";
        ss_json << "Jan  7 06:47:40 2020 GMT";
        ss_json << "\",";

        ss_json << "\"serverCrtName\": ";
        ss_json << "\"";
        ss_json << "server.crt";
        ss_json << "\",";

        ss_json << "\"serverEndDate\": ";
        ss_json << "\"";
        ss_json << "Jan  7 06:47:40 2019 GMT";
        ss_json << "\"";

        ss_json << "}}";

        return ss_json.str();
    }

    return build_openvpn_rsp_json(status, "failed");
}


std::string json_handle_openvpn_cfg_client(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::string status      = "failed";

    if (method && (strcmp(method, "POST") == 0) && contentType)
    {
        // POST
        std::string data;

        if (get_post_data(request, data)) {
            try {

                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                std::string clientCrtStr = POSTParser.GetField("clientCrtName")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientCrtName, clientCrtStr.c_str(), clientCrtStr.length());

                std::string countryCrtStr = POSTParser.GetField("clientCountry")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientCountry, countryCrtStr.c_str(), countryCrtStr.length());

                std::string clientProvinceStr = POSTParser.GetField("clientProvince")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientProvince, clientProvinceStr.c_str(), clientProvinceStr.length());

                std::string clientLocalityStr = POSTParser.GetField("clientLocality")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientLocality, clientLocalityStr.c_str(), clientLocalityStr.length());

                std::string clientOrganizationStr = POSTParser.GetField("clientOrganization")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientOrganization, clientOrganizationStr.c_str(), clientOrganizationStr.length());

                std::string clientCommonNameStr = POSTParser.GetField("clientCommonName")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientCommonName, clientCommonNameStr.c_str(), clientCommonNameStr.length());

                std::string clientEmailStr = POSTParser.GetField("clientEmail")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientEmail, clientEmailStr.c_str(), clientEmailStr.length());

                std::string endDateCrtStr = POSTParser.GetField("clientCrtEndDate")->GetTextTypeContent();
                strncpy(openvpnCfgClient.clientCrtEndDate, endDateCrtStr.c_str(), endDateCrtStr.length());

                printf("openvpnCfgClient.clientCrtName: %s\n",openvpnCfgClient.clientCrtName);
                printf("openvpnCfgClient.clientCountry: %s\n",openvpnCfgClient.clientCountry);
                printf("openvpnCfgClient.clientProvince: %s\n",openvpnCfgClient.clientProvince);
                printf("openvpnCfgClient.clientLocality: %s\n",openvpnCfgClient.clientLocality);
                printf("openvpnCfgClient.clientOrganization: %s\n",openvpnCfgClient.clientOrganization);
                printf("openvpnCfgClient.clientCommonName: %s\n",openvpnCfgClient.clientCommonName);
                printf("openvpnCfgClient.clientEmail: %s\n",openvpnCfgClient.clientEmail);
                printf("openvpnCfgClient.clientCrtEndDate: %s\n",openvpnCfgClient.clientCrtEndDate);

                return build_openvpn_rsp_json(status, "success");

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return build_openvpn_rsp_json(status, e.GetError().c_str());
            }

        } else {
            syslog(LOG_ERR, "Failed to get data from browser\n");
            return build_openvpn_rsp_json(status, "Failed to get data from browser");
        }

    }
    else if (method && (strcmp(method, "GET") == 0))
    {
        std::ostringstream ss_json;

        ss_json << "{\"json_openvpn_config\": {";

        ss_json << "\"clientCrtName\": ";
        ss_json << "\"";
        ss_json << "client.crt";
        ss_json << "\", ";

        ss_json << "\"clientCountry\": ";
        ss_json << "\"";
        ss_json << "VN";
        ss_json << "\", ";

        ss_json << "\"clientProvince\": ";
        ss_json << "\"";
        ss_json << "Viet name";
        ss_json << "\", ";

        ss_json << "\"clientLocality\": ";
        ss_json << "\"";
        ss_json << "HCM City";
        ss_json << "\",";

        ss_json << "\"clientOrganization\": ";
        ss_json << "\"";
        ss_json << "Example";
        ss_json << "\",";

        ss_json << "\"clientCommonName\": ";
        ss_json << "\"";
        ss_json << "Client";
        ss_json << "\",";

        ss_json << "\"clientEmail\": ";
        ss_json << "\"";
        ss_json << "client@example.com";
        ss_json << "\",";

        ss_json << "\"clientCrtEndDate\": ";
        ss_json << "\"";
        ss_json << "Jan  7 06:47:40 2019 GMT";
        ss_json << "\"";

        ss_json << "}}";

        return ss_json.str();
    }

    return build_openvpn_rsp_json(status, "failed");
}
