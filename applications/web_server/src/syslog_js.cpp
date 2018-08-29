/*
 * syslog_js.cpp
 *
 *  Created on: Aug 29, 2018
 *      Author: hhdang
 */
#include <string.h>
#include <string>
#include <sstream>

#include "fcgi.h"

std::string json_handle_syslog(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    std::ostringstream ss_json;

    if (method && (strcmp(method, "GET") == 0)) {
        ss_json << "{\"syslog\": \"";
        ss_json << "aaaaaaaaaaaaaaaaaaaaaaaa";
        ss_json << "\"}";
    }

    return ss_json.str();
}
