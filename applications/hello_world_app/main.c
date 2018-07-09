/* Compile with: gcc -Wall -lfcgi fastcgi.c -o fastcgi
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcgiapp.h>

#define printfcgi(...) FCGX_FPrintF(request->out, __VA_ARGS__)
#define get_param(KEY) FCGX_GetParam(KEY, request->envp)

void handle_request(FCGX_Request *request) {
    printfcgi("Content-Type: text/html; charset=utf-8\r\n\r\n");
    printfcgi(""
            "<!DOCTYPE html>"
            "<html>"
            "<head>"
            "<title>Welcome</title>"
            "</head>"
            "<body>"
            "<h1>Hello World!</h1>"
            "<p>This is an combination between Hiawatha and FastCGI\n</p>"
            "</body>"
            "</html>"
            );
    printfcgi("\n");
}

int main(void) {
    int sock;
    FCGX_Request request;

    FCGX_Init();
    sock = FCGX_OpenSocket(":2005", 5);
    FCGX_InitRequest(&request, sock, 0);

    while (FCGX_Accept_r(&request) >= 0) {
        handle_request(&request);
        FCGX_Finish_r(&request);
    }

    return EXIT_SUCCESS;
}
