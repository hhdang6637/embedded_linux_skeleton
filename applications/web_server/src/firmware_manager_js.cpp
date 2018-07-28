/*
 * firmware.cpp
 *
 *  Created on: Jul 25, 2018
 *      Author: nmhien
 */
#include <string>
#include <sstream>

#include <fcgiapp.h>
#include <syslog.h>

#include "firmware_manager_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "rpcUnixClient.h"
#include "rpcMessageFirmware.h"


static int do_firmware_upgrade(const std::string &filename)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageFirmware msg;

    app::rpcMessageFirmware_t info;
    info.action = app::rpcFirmwareActionType::DO_UPGRADE;

    msg.setFirmwareName(filename);
    msg.setFirmwareInfo(info);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_INFO, "something went wrong: doRpc\n");
        return 0;
    }

    return 1;
}

/**
 * \return 0 on error
 */
static int parse_and_save_file(const char *data, const char *contentType, const int len, std::string &filename)
{
    try {
        MPFD::Parser POSTParser;

        POSTParser.SetTempDirForFileUpload("/tmp");

        POSTParser.SetMaxCollectedDataLength(32 * 1024 * 1024); // 32MB

        POSTParser.SetContentType(contentType);

        POSTParser.AcceptSomeData(data, len);

        // Now see what we have:
        std::map<std::string, MPFD::Field *> fields = POSTParser.GetFieldsMap();

        for (auto const &it : fields) {
            char syslog_message[256];

            if (fields[it.first]->GetType() == MPFD::Field::TextType) {

                snprintf(syslog_message, 256, "Got text field: [ %s ], value: [ %s ]\n", it.first.c_str(),
                         fields[it.first]->GetTextTypeContent().c_str());

            } else {

                snprintf(syslog_message, 256, "Got file field: [ %s ], Filename: [ %s ]\n", it.first.c_str(),
                         fields[it.first]->GetTempFileName().c_str());

                filename = fields[it.first]->GetTempFileName();

            }

            syslog(LOG_INFO, syslog_message);
        }

    } catch (MPFD::Exception e) {

        syslog(LOG_ERR, "%s\n", e.GetError().c_str());
        return 0;

    }

    return 1;
}

static bool get_post_data(FCGX_Request *request, std::string &data)
{
    const char *contentLenStr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    int         contentLength = 0;

    if (contentLenStr) {
        contentLength = strtol(contentLenStr, NULL, 10);
    }

    for (int len = 0; len < contentLength; len++) {
        int ch = FCGX_GetChar(request->in);

        if (ch < 0) {

            syslog(LOG_ERR, "Failed to get file content\n");
            return false;

        } else {
            data += ch;
        }
    }

    return true;
}

std::string json_handle_firmware_upgrade(FCGX_Request *request)
{
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (get_post_data(request, data)) {

            std::string filename;

            if (parse_and_save_file(data.c_str(), contentType, data.size(), filename)) {

                if (do_firmware_upgrade(filename)) {
                    return "succeeded";
                }

            }
        }
    }

    syslog(LOG_ERR, "Failed to upgrade firmware\n");

    return "failed";
}

std::string json_handle_firmware_status(FCGX_Request *request)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageFirmware msg;

    app::rpcMessageFirmware_t info;
    info.action = app::rpcFirmwareActionType::GET_STATUS;

    msg.setFirmwareInfo(info);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_INFO, "something went wrong: doRpc\n");
        return "";
    }

    std::ostringstream ss_json;
    ss_json << "{\"json_firmware_status\": {";

    ss_json << "\"status\": ";
    ss_json << "\"";
    ss_json << msg.statusToString(msg.getFirmwareInfo().status);
    ss_json << "\", ";

    ss_json << "\"result\": ";
    ss_json << "\"";
    ss_json << msg.resultToString(msg.getFirmwareInfo().result);
    ss_json << "\"";

    ss_json << "}}";

    return ss_json.str();
}

