/*
 * firmware.cpp
 *
 *  Created on: Jul 25, 2018
 *      Author: nmhien
 */
#include <fcgiapp.h>

#include "Parser.h"
#include "Field.h"
#include "Exception.h"
#include "firmware.h"

/**
 * \return 0 on error
 */
static int process_file_data(const char *input, const char *contentType)
{
    MPFD::Parser *POSTParser;
    try {
        POSTParser = new MPFD::Parser();
        POSTParser->SetTempDirForFileUpload("/tmp");
        POSTParser->SetMaxCollectedDataLength(32*1024*1024);

        POSTParser->SetContentType(contentType);

        const int ReadBufferSize = strlen(input);

        POSTParser->AcceptSomeData(input, ReadBufferSize);

        // Now see what we have:
        std::map<std::string,MPFD::Field *> fields=POSTParser->GetFieldsMap();

        std::cout << "Have " << fields.size() << " fields\n\r";

        std::map<std::string,MPFD::Field *>::iterator it;
        for (it=fields.begin();it!=fields.end();it++) {
            if (fields[it->first]->GetType()==MPFD::Field::TextType) {
                std::cout<<"Got text field: ["<<it->first<<"], value: ["<< fields[it->first]->GetTextTypeContent() <<"]\n";
            } else {
                std::cout<<"Got file field: ["<<it->first<<"] Filename:["<<fields[it->first]->GetFileName()<<"] \n";
                std::cout << fields[it->first]->GetTempFileName() << std::endl;
            }
        }
    } catch (MPFD::Exception e) {
        std::cout << "Parsing input error: " << e.GetError() << std::endl;
        return 0;
    }

    return 1;
}

/**
 * \return 0 on error
 */
int handle_firmware_upgrade(FCGX_Request *request)
{
    const char *contentLenStr  = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    const char *contentType    = FCGX_GetParam("CONTENT_TYPE", request->envp);

    std::string data;
    int         contentLength = 0;

    if (contentLenStr) {
        contentLength = strtol(contentLenStr, NULL, 10);
    }

    for (int len = 0; len < contentLength; len++) {
        int ch = FCGX_GetChar(request->in);

        if (ch < 0) {
            std::cerr << "Failed to get file content" << std::endl;
            return 0;

        } else {
            data  += ch;
        }
    }

    if (contentType) {
        process_file_data(data.c_str(), contentType);
    }

    return 1;
}