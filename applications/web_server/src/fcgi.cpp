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

#include "simplewebfactory.h"
#include "fcgi.h"
#include "firmware.h"

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

static void handle_request(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *request_uri = FCGX_GetParam("REQUEST_URI", request->envp);

    if (method && (strcmp(method, "POST") == 0)) {

        printf("request_uri: %s\n", request_uri);
        if (strcmp(request_uri, "/firmware_upgrade") == 0) {
            if (handle_firmware_upgrade(request)) {
                printfcgi("HTTP/1.1 200 OK\r\n\r\n");
            } else {
                printfcgi("HTTP/1.1 400 Bad Request\r\n\r\n");
            }

            return;
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

