/*
 * openvpn_client_js.cpp
 *
 *  Created on: March 11, 2019
 *      Author: nmhien
 */
#include <string>
#include <sstream>

#include <fcgiapp.h>
#include <syslog.h>

#include "simplewebfactory.h"
#include "openvpn_client_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "rpcUnixClient.h"
#include "rpcMessageFirmware.h"
#include "fcgi.h"

/**
 * \return 0 on error
 */
static int parse_and_save_file(const char *data, const char *contentType, const int len, std::string &filename, bool &enable)
{
    try {
        MPFD::Parser POSTParser;

        POSTParser.SetTempDirForFileUpload("/tmp");

        POSTParser.SetContentType(contentType);

        POSTParser.AcceptSomeData(data, len);

        enable = (POSTParser.GetFieldText("enable") == "true" ? true : false);

        MPFD::Field *filename_field = POSTParser.GetField("filename");
        if (filename_field) {
            filename = filename_field->GetTempFileName();
        }

    } catch (MPFD::Exception &e) {

        syslog(LOG_ERR, "%s\n", e.GetError().c_str());
        return 0;

    }

    return 1;
}

std::string json_handle_import_openvpn_client(FCGX_Request *request)
{
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (simpleWebFactory::get_post_data(request, data)) {

            std::string filename;
            bool enable;

            if (parse_and_save_file(data.c_str(), contentType, data.size(), filename, enable)) {

                // TODO

                return "succeeded";
            }
        }
    }

    return "failed";
}
