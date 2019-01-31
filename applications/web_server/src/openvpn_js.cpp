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
#include "conversion.h"

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

    app::openvpnCfg_t openvpnCfg;

    if (method && (strcmp(method, "POST") == 0) && contentType)
    {
        // POST
        std::string data;

        if (get_post_data(request, data)) {
            try {

                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);
                POSTParser.AcceptSomeData(data.c_str(), data.size());

                openvpnCfg.state = POSTParser.GetFieldText("enable_vpn").compare("true") == 0 ? 1 : 0;
                openvpnCfg.port = std::atoi(POSTParser.GetFieldText("port").c_str());

                if (app::rpcMessageOpenvpnCfg::rpcSetOpenvpnCfg_data(*app::rpcUnixClient::getInstance(), openvpnCfg))
                {
                    status = "succeeded";
                }

                return build_openvpn_rsp_json(status, "see the syslog to get detail");

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
        app::openvpnCfg_t openvpnCfg_data;

        app::rpcMessageOpenvpnCfg::rpcGetOpenvpnCfg_data(*app::rpcUnixClient::getInstance(), openvpnCfg_data);

        ss_json << "{\"json_openvpn_config\": {";

        ss_json << "\"state\":";
        ss_json << openvpnCfg_data.state;
        ss_json << ", ";

        ss_json << "\"port\":";
        ss_json << openvpnCfg_data.port;

        ss_json << "}}";

        return ss_json.str();
    }

    return build_openvpn_rsp_json(status, "failed");
}

std::string json_handle_openvpn_rsa(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::string status      = "failed";

    if (method && (strcmp(method, "GET") == 0)) {
        std::ostringstream ss_json;
        app::openvpn_rsa_info_t openvpnRsa_info;

        app::rpcMessageOpenvpnRsaInfo::rpcGetOpenvpnRsaInfo(*app::rpcUnixClient::getInstance(), openvpnRsa_info);

        ss_json << "{\"json_openvpn_rsa\": {";

        ss_json << "\"ca_name\": ";
        ss_json << "\"";
        ss_json << openvpnRsa_info.ca_subjects;
        ss_json << "\", ";

        ss_json << "\"server_name\": ";
        ss_json << "\"";
        ss_json << openvpnRsa_info.server_subjects;
        ss_json << "\"";

        ss_json << "}}";

        return ss_json.str();

    } else if (method && (strcmp(method, "POST") == 0) && contentType) {

        if (app::rpcMessageOpenvpnRsaInfo::rpcReGenOpevpnRsaInfo(*app::rpcUnixClient::getInstance())) {
            status = "succeeded";
        }

        return build_openvpn_rsp_json(status, "success");

    }

    return build_openvpn_rsp_json(status, "failed");
}

std::string json_handle_openvpn_client_cert(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::string status      = "failed";

    if (method && (strcmp(method, "GET") == 0)) {
        std::ostringstream ss_json;
        std::list<app::openvpn_client_cert_t> certs;
        size_t counter = 0;

        app::rpcMessageOpenvpnClientCerts::rpcGetOpenvpnClientCerts(*app::rpcUnixClient::getInstance(), certs);

        ss_json << "{\"json_client_cert\": [";

        for (auto const &cert : certs) {

            ss_json << "{";
            ss_json << "\"name\": ";
            ss_json << "\"";
            ss_json << cert.common_name;
            ss_json << "\", ";

            ss_json << "\"email\": ";
            ss_json << "\"";
            ss_json << cert.email;
            ss_json << "\", ";

            ss_json << "\"state\": ";
            ss_json << "\"";
            ss_json << app::rpcMessageOpenvpnClientCerts::openVpnClientCertStateChar2Str(cert.state);
            ss_json << "\", ";

            ss_json << "\"expire\": ";
            ss_json << "\"";
            ss_json << ASN1_to_string(cert.expire_date);
            ss_json << "\"";
            ss_json << "}";

            if (++counter < certs.size()) {
                ss_json << ",";
            }
        }

        ss_json << "]}";

        return ss_json.str();

    } else if (method && (strcmp(method, "POST") == 0) && contentType) {
        std::string data;

        if (get_post_data(request, data)) {
            try {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);
                POSTParser.AcceptSomeData(data.c_str(), data.size());

                app::openvpn_client_cert_t cert = app::openvpn_client_cert_t();
                string_copy(cert.common_name, POSTParser.GetFieldText("common_name"), sizeof(cert.common_name));
                string_copy(cert.email, POSTParser.GetFieldText("email"), sizeof(cert.email));

                if (app::rpcMessageOpenvpnClientCerts::rpcGenOpevpnClientCert(
                        *app::rpcUnixClient::getInstance(), cert)) {
                    status = "succeeded";
                }

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

    return build_openvpn_rsp_json(status, "failed");
}
