#include <string.h>
#include <string>
#include <sstream>
#include <syslog.h>
#include <iostream>
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"

#include "fcgi.h"
#include "simplewebfactory.h"

static inline std::string build_user_rsp_json(std::string status, std::string message = "") {
    std::ostringstream ss_json;
    ss_json << "{";
    ss_json << "\"status\": \"" << status <<"\",";
    ss_json << "\"message\": \""<< message <<"\"";
    ss_json << "}";

    return ss_json.str();
}

std::string json_handle_login(FCGX_Request *request)
{
    const char *method = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::ostringstream ss_json;

    std::string status = "failed";

    if (method && (strcmp(method, "POST") == 0)) {
        std::string data;

        if (simpleWebFactory::get_post_data(request, data)) {

            std::string username, password;
            try
            {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                username = POSTParser.GetField("username")->GetTextTypeContent();
                password = POSTParser.GetField("password")->GetTextTypeContent();


            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());

                return build_user_rsp_json(status, "Login failed");
            }

            if (username.compare("admin") == 0 && password.compare("admin") == 0) {
                status = "succeeded";
                return build_user_rsp_json(status);
            } else {
                return build_user_rsp_json(status, "Incorrect username or password");
            }
        }
    }

    return ss_json.str();
}
