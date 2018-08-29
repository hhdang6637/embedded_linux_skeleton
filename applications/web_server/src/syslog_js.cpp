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
#include "simplewebfactory.h"

static void jsonQuote(std::ostringstream &ss, std::string str)
{
    ss << '"';
    for (char& c : str) {
        switch (c)
        {
        case '\\':
        case '"':
            ss << '\\';
            ss << c;
            break;
        case '/':
            //                if (b == '<') {
            ss << '\\';
            //                }
            ss << c;
            break;
        case '\b':
            ss << "\\b";
            break;
        case '\t':
            ss << "\\t";
            break;
        case '\n':
            ss << "\\n";
            break;
        case '\f':
            ss << "\\f";
            break;
        case '\r':
            ss << "\\r";
            break;
        default:
            ss << c;
        }
    }
    ss << '"';
}

std::string json_handle_syslog(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    std::ostringstream ss_json;

    if (method && (strcmp(method, "GET") == 0)) {
        std::string syslog_str;
        ss_json << "{\"syslog\": ";
        if (simpleWebFactory::file_to_string("/tmp/messages", syslog_str)) {
            jsonQuote(ss_json, syslog_str);
        }
        ss_json << "}";
    }

    return ss_json.str();
}
