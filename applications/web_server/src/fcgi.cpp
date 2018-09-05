/*
 * fcgi.cpp
 *
 *  Created on: Jul 21, 2018
 *      Author: hhdang
 */

#include <sys/stat.h>
#include <syslog.h>
#include <string.h>
#include <fcgiapp.h>

#include <iostream>

#include "simplewebfactory.h"
#include "fcgi.h"

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

static void fcgi_accept_loop()
{
    while (FCGX_Accept_r(&fcgi_request) >= 0) {

        simpleWebFactory::getInstance()->handle_request(&fcgi_request);
        FCGX_Finish_r(&fcgi_request);

    }
}

void fcgi_start()
{
    fcgi_init();
    fcgi_accept_loop();
}

static const char * fcgi_form_varable_search(FCGX_Request *request, const char *name)
{
    const char *arglist;

    int lenName = strlen(name);
    const char *start, *ptr;

    arglist = FCGX_GetParam("QUERY_STRING", request->envp);

    if (arglist == NULL) {
        return NULL;
    }

    start = arglist;
    while(*arglist && (ptr = strstr(arglist, name))) {
        if(ptr[lenName] == '=' &&
           (ptr == start ||     /* ^name= match OR*/
            ptr[-1] == '&'))    /* &name= match */
            return ptr + lenName + 1; /* Match, skip past "name=" */
        /* False match, advance past match */
        arglist = ptr + lenName;
    }

    return NULL;
}

unsigned int fcgi_form_varable_str(FCGX_Request *request, const char *name, char *buff, unsigned int len)
{
    unsigned int datalen = 0;

    const char *value = fcgi_form_varable_search(request, name);
    if(value) {
        while(value[datalen] && (value[datalen] != '&')) {
            datalen++;
        }

        if (datalen >  0) {

            if (datalen > len - 1) {
                datalen = len - 1;
            }

            memcpy(buff, value, datalen);
            buff[datalen] = '\0';
        }
    }

    return datalen;
}

bool get_post_data(FCGX_Request *request, std::string &data)
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
