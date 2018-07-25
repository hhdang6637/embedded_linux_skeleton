/*
 * firmware.cpp
 *
 *  Created on: Jul 25, 2018
 *      Author: nmhien
 */
#include <fcgiapp.h>
#include <syslog.h>

#include "Parser.h"
#include "Field.h"
#include "Exception.h"
#include "firmware.h"

/**
 * \return 0 on error
 */
static int process_file_data(const char *data, const char *contentType, const int len)
{
    try {
        MPFD::Parser *POSTParser;

        POSTParser = new MPFD::Parser();

        POSTParser->SetTempDirForFileUpload("/tmp");

        POSTParser->SetMaxCollectedDataLength(32 * 1024 * 1024); // 32MB

        POSTParser->SetContentType(contentType);

        POSTParser->AcceptSomeData(data, len);

        // Now see what we have:
        std::map<std::string, MPFD::Field *> fields = POSTParser->GetFieldsMap();

        for (auto const &it : fields) {
            char syslog_message[256];

            if (fields[it.first]->GetType() == MPFD::Field::TextType) {

                snprintf(syslog_message, 256,
                        "Got text field: [ %s ], value: [ %s ]\n",
                        it.first.c_str(),
                        fields[it.first]->GetTextTypeContent().c_str());

            } else {

                snprintf(syslog_message, 256,
                        "Got file field: [ %s ], Filename: [ %s ]\n",
                        it.first.c_str(),
                        fields[it.first]->GetTempFileName().c_str());

            }

            syslog(LOG_INFO, syslog_message);
        }
    } catch (MPFD::Exception e) {

        syslog(LOG_ERR, "%s\n", e.GetError().c_str());
        return 0;

    }

    return 1;
}

/**
 * \return 0 on error
 */
int handle_firmware_upgrade(FCGX_Request *request)
{
    const char *contentLenStr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    const char *contentType   = FCGX_GetParam("CONTENT_TYPE", request->envp);

    std::string data;
    int         contentLength = 0;

    if (contentLenStr) {
        contentLength = strtol(contentLenStr, NULL, 10);
    }

    for (int len = 0; len < contentLength; len++) {
        int ch = FCGX_GetChar(request->in);

        if (ch < 0) {

            syslog(LOG_ERR, "Failed to get file content\n");
            return 0;

        } else {
            data += ch;
        }
    }

    if (contentType) {
        process_file_data(data.c_str(), contentType, data.size());
    }

    return 1;
}
