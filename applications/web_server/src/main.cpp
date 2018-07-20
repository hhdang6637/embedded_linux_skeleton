#include <syslog.h>
#include <sys/stat.h>
#include <fcgiapp.h>

#include <iostream>
#include "simplewebfactory.h"

static int fcgi_sock = -1;
static FCGX_Request fcgi_request;

static void fcgi_init() {

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

static void handle_request(FCGX_Request *request) {

    const char* header = simpleWebFactory::getInstance()->get_html_header_str();
    const char* footer = simpleWebFactory::getInstance()->get_html_footer_str();
    const char* navbar = simpleWebFactory::getInstance()->get_html_navbar_str();

    printfcgi("Content-Type: text/html; charset=utf-8\r\n\r\n");
    printfcgi(""
            "<!doctype html>"
            "<html lang=\"en\">"
            //head
            "%s"
            // body
            "<body>"
            // navbar
            "%s"
"    <main role=\"main\" class=\"container\">"
"      <div class=\"starter-template\">"
"        <h1>Bootstrap starter template</h1>"
"        <p class=\"lead\">Use this document as a way to quickly start any new project.<br> All you get is this text and a mostly barebones HTML document.</p>"
"      </div>"
"    </main><!-- /.container -->"
            // footer
            "%s"
            "</body>"
            "</html>", header, navbar, footer
            );
    printfcgi("\n");
}

static void fcgi_accept_loop() {
    while (FCGX_Accept_r(&fcgi_request) >= 0) {

#if 0
        char **e = fcgi_request.envp;
        while (*e) {
            std::cout << "\n" << *e;
            e++;
        }
#endif
        std::cout << std::endl;

//        const char *script      = FCGX_GetParam("SCRIPT_NAME", fcgi_request.envp);
//        const char *http_scheme = FCGX_GetParam("HTTP_SCHEME", fcgi_request.envp);
//        const char *http_host   = FCGX_GetParam("HTTP_HOST",   fcgi_request.envp);
//        const char *request_uri = FCGX_GetParam("REQUEST_URI", fcgi_request.envp);
//        handle_request(&request);
        handle_request(&fcgi_request);
        FCGX_Finish_r(&fcgi_request);
    }
}

int main(int argc, char const *argv[])
{
    openlog("web_handler", 0, LOG_USER);
    fcgi_init();
    fcgi_accept_loop();
    return 0;
}
