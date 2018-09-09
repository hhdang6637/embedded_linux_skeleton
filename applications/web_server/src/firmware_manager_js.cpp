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

#include "simplewebfactory.h"
#include "firmware_manager_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "rpcUnixClient.h"
#include "rpcMessageFirmware.h"
#include "fcgi.h"


static int do_firmware_upgrade(const std::string &filename, const bool &reboot)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageFirmware msg;

    app::rpcMessageFirmwareData_t msgData = app::rpcMessageFirmwareData_t();

    msgData.reboot = reboot;
    msgData.fwName = filename;

    msg.setFirmwareMsgAction(app::rpcFirmwareActionType::DO_UPGRADE);

    msg.setFirmwareMsgData(msgData);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return 0;
    }

    return 1;
}

/**
 * \return 0 on error
 */
static int parse_and_save_file(const char *data, const char *contentType, const int len, std::string &filename, bool &reboot)
{
    try {
        MPFD::Parser POSTParser;

        POSTParser.SetTempDirForFileUpload("/tmp");

        POSTParser.SetMaxCollectedDataLength(64 * 1024 * 1024); // 64MB

        POSTParser.SetContentType(contentType);

        POSTParser.AcceptSomeData(data, len);

        reboot = (POSTParser.GetField("reboot")->GetTextTypeContent() == "true" ? true : false);

        filename = POSTParser.GetField("filename")->GetTempFileName();
    } catch (MPFD::Exception &e) {

        syslog(LOG_ERR, "%s\n", e.GetError().c_str());
        return 0;

    }

    return 1;
}

std::string json_handle_firmware_upgrade(FCGX_Request *request)
{
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (simpleWebFactory::get_post_data(request, data)) {

            std::string filename;
            bool reboot;

            if (parse_and_save_file(data.c_str(), contentType, data.size(), filename, reboot)) {

                if (do_firmware_upgrade(filename, reboot)) {
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

    msg.setFirmwareMsgAction(app::rpcFirmwareActionType::GET_STATUS);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return "";
    }

    std::ostringstream ss_json;
    ss_json << "{\"json_firmware_status\": {";

    ss_json << "\"status\": ";
    ss_json << "\"";
    ss_json << app::rpcMessageFirmware::statusToString(msg.getFirmwareMsgData().status);
    ss_json << "\", ";

    ss_json << "\"result\": ";
    ss_json << "\"";
    ss_json << app::rpcMessageFirmware::resultToString(msg.getFirmwareMsgData().result);
    ss_json << "\"";

    ss_json << "}}";

    return ss_json.str();
}

std::string json_handle_firmware_info(FCGX_Request *request)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageFirmware msg;

    msg.setFirmwareMsgAction(app::rpcFirmwareActionType::GET_INFO);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return "";
    }

    std::ostringstream ss_json;
    ss_json << "{\"json_firmware_info\": {";

    ss_json << "\"desc\": ";
    ss_json << "\"";
    ss_json << msg.getFirmwareMsgData().fwDesc;
    ss_json << "\", ";

    ss_json << "\"date\": ";
    ss_json << "\"";
    ss_json << msg.getFirmwareMsgData().fwDate;
    ss_json << "\"";

    ss_json << "}}";

    return ss_json.str();
}
