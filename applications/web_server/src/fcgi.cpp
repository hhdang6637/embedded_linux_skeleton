/*
 * fcgi.cpp
 *
 *  Created on: Jul 21, 2018
 *      Author: hhdang
 */

#include <sys/stat.h>
#include <syslog.h>
#include <fcgiapp.h>
#include <string.h>

#include <iostream>
#include <fstream>
#include <algorithm>

#include "simplewebfactory.h"
#include "fcgi.h"
#include "Parser.h"
#include "Field.h"
#include "Exception.h"

static int fcgi_sock = -1;
static FCGX_Request fcgi_request;

static void fcgi_init()
{
    const char *sockname = "/tmp/web_handler.socket";

    FCGX_Init();

    if ((fcgi_sock = FCGX_OpenSocket(sockname, 10)) < 0) {
        syslog(LOG_ERR, "fcgi init failed");
        exit(-1);
    }

    chmod(sockname, 0777);

    FCGX_InitRequest(&fcgi_request, fcgi_sock, 0);
}

#define printfcgi(...) FCGX_FPrintF(request->out, __VA_ARGS__)
#define get_param(KEY) FCGX_GetParam(KEY, request->envp)

static int process_data(const char *input, const char *contentType)
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
        // FinishConnectionProcessing();
        return 0;
    }

    return 1;
}

static std::string get_content_type(FCGX_Request *request)
{
    std::string contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);

    std::string retStr      = "multipart/form-data; ";

    std::string boundary = contentType.substr(contentType.find("boundary"));

    // rm -------------
    boundary.erase(std::remove(boundary.begin(), boundary.end(), '-'), boundary.end());

    retStr += boundary;

    return retStr;
}

static void handle_firmware_upgrade(FCGX_Request *request)
{
    const char *contentLength = FCGX_GetParam("CONTENT_LENGTH", request->envp);

    int content_len = 0;

    if (contentLength) {
        content_len = strtol(contentLength, NULL, 10);
    }

    std::string post_data;

    for (int len = 0; len < content_len; len++) {
        int ch = FCGX_GetChar(request->in);

        if (ch < 0) {
            content_len = len;
            return;

        } else {
            post_data  += ch;
        }
    }

    process_data(post_data.c_str(), get_content_type(request).c_str());
}

static void handle_request(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *request_uri = FCGX_GetParam("REQUEST_URI", request->envp);

    if (method && (strcmp(method, "POST") == 0)) {

        printf("request_uri: %s\n", request_uri);
        if (strcmp(request_uri, "/firmware_upgrade") == 0) {
            handle_firmware_upgrade(request);
        }

    }

    simpleWebFactory *web = simpleWebFactory::getInstance();

    const char *response_content = web->get_html_str(request_uri);

    if (response_content != NULL) {

        printfcgi("Content-Type: text/html; charset=utf-8\r\n\r\n");
        printfcgi("%s", response_content);

    } else if ((response_content = web->get_js_str(request_uri)) != NULL) {

        printfcgi("Content-Type: application/json; charset=utf-8\r\n\r\n");
        printfcgi("%s", response_content);

    } else {
        printfcgi("HTTP/1.1 404 Not Found\r\n\r\n");
    }

}

static void fcgi_accept_loop()
{
    while (FCGX_Accept_r(&fcgi_request) >= 0) {

        handle_request(&fcgi_request);
        FCGX_Finish_r(&fcgi_request);

    }
}

void fcgi_start()
{
    fcgi_init();
    fcgi_accept_loop();
}

