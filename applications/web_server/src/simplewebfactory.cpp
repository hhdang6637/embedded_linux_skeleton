/*
 * simplewebfactory.cpp
 *
 *  Created on: Jul 20, 2018
 *      Author: hhdang
 */
#include <string.h>
#include <syslog.h>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"

#include "simplewebfactory.h"
#include "rpcUnixClient.h"
#include "rpcMessageAuthentication.h"

#include "firmware_manager_js.h"

bool simpleWebFactory::file_to_string(std::string filename, std::string &output)
{
    std::string line;
    std::ifstream file(filename);
    std::ostringstream ss;

    output.clear();

    if (file.is_open()) {
        while (getline(file, line)) {
            ss << line;
            ss << std::endl;
        }
        file.close();
        output = ss.str();
    } else {
        return false;
    }

    return true;
}

simpleWebFactory::simpleWebFactory()
{
    std::string html_file;

    html_file = INTERNAL_RESOURCE"/header.html";
    simpleWebFactory::file_to_string(html_file, this->html_header_str);

    html_file = INTERNAL_RESOURCE"/footer.html";
    simpleWebFactory::file_to_string(html_file, this->html_footer_str);

    html_file = INTERNAL_RESOURCE"/navbar.html";
    simpleWebFactory::file_to_string(html_file, this->html_navbar_str);

    this->init_url_html_map();
    this->init_url_js_map();
}

simpleWebFactory::~simpleWebFactory()
{

}

simpleWebFactory *simpleWebFactory::s_instance = 0;

simpleWebFactory* simpleWebFactory::getInstance()
{
    if (s_instance == 0) {
        s_instance = new simpleWebFactory();
    }

    return s_instance;
}

static void redirect(FCGX_Request *request, std::string url_redirect)
{
    std::string http_post(FCGX_GetParam("HTTP_HOST", request->envp));

    std::string redirect_location;
    std::string content_length;
    std::ostringstream ss_html;

    FCGX_FPrintF(request->out, "HTTP/1.1 301 Moved Permanently\r\n");

    redirect_location = "Location: " + url_redirect + "\r\n";
    FCGX_FPrintF(request->out, redirect_location.c_str());

    FCGX_FPrintF(request->out, "Content-Type: text/html\r\n");

    ss_html << "<html>\n";
    ss_html << "<head>\n";

    ss_html << "<title>Moved</title>\n";

    ss_html << "</head>\n";
    ss_html << "<body>\n";
    ss_html << "<h1>Moved</h1>\n";

    ss_html << "<p>This page has moved to";
    ss_html << "<a href=\"http://" + http_post + url_redirect + "\">http://" + http_post + url_redirect + "</a>";
    ss_html << "</p>\n";

    ss_html << "</body>\n";
    ss_html << "</html> \n";

    content_length = "Content-Length: " + std::to_string(ss_html.str().length()) + "\r\n\r\n";

    FCGX_FPrintF(request->out, content_length.c_str());

    FCGX_FPrintF(request->out, "%s", ss_html.str().c_str());
}

typedef struct {
    char username[32];
    long int session_id;
} session_entry;

static session_entry session_entries[10];

static bool session_valid(FCGX_Request *request)
{
    char *cookie;
    char *session_text_tmp;
    char *session_text;
    long int session_id = 0;
    int i;

    cookie = FCGX_GetParam("HTTP_COOKIE", request->envp);
    if (cookie) {
        session_text_tmp = strstr(cookie, "session_id=");
        if (session_text_tmp) {
            session_text_tmp += (sizeof("session_id=") - 1);
            session_text = strtok(session_text_tmp, ";");
            if (session_text) {
                session_id = strtol(session_text, NULL, 10);
            }
            // syslog(LOG_DEBUG, "session_id = %ld\n", session_id);
        }

        if (session_id > 0) {
            for (i = 0; i < 10; i++) {
                if (session_entries[i].session_id == session_id) {
                    return true;
                }
            }
        }
    }

    return false;
}

static long int session_id_generator(const char *username)
{
    long int session_id, i;
    bool unique = false;

    srandom(time(NULL));

    do {
        session_id = random();

        if (session_id > 0xFFFF) {
            unique = true;

            for (i = 0; i < 10; i++) {
                if (session_entries[i].session_id == session_id) {
                    unique = false;
                    break;
                }
            }
        }
    } while (unique == false);

    for (i = 0; i < 10; i++) {
        if (session_entries[i].session_id == 0) {
            session_entries[i].session_id = session_id;
            snprintf(session_entries[i].username, 32, "%s", username);
            return session_id;
        }
    }

    return -1;
}

static long int authenticate(std::string &username, std::string &password)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageAuthentication msg;

    msg.setUsername(username);
    msg.setPasswd(password);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if (msg.getAuthenticationMsgResult() == app::rpcMessageAuthenticationResultType::SUCCEEDED_LOGIN) {
        return session_id_generator(username.c_str());
    }

    return -1;
}

static void hanlde_login_request(FCGX_Request *request)
{
    const char *method = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);

    if (method && (strcmp(method, "POST") == 0)) {
        std::string data;

        if (simpleWebFactory::get_post_data(request, data)) {

            std::string username, password;
            try
            {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                username = POSTParser.GetField("username")->GetTextTypeContent();
                password = POSTParser.GetField("password")->GetTextTypeContent();

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
            }

            long int session_id = authenticate(username, password);
            if (session_id > 0) {
                FCGX_FPrintF(request->out, "HTTP/1.1 301 Moved Permanently\r\n");
                FCGX_FPrintF(request->out, "Location: /pages/home\r\n");
                FCGX_FPrintF(request->out, "Set-Cookie: session_id=%d; path=/\r\n", session_id);
                FCGX_FPrintF(request->out, "Content-Type: text/html; charset=utf-8\r\n\r\n");
            } else {
                redirect(request, "/pages/login");
            }
        }
    }
}

bool simpleWebFactory::get_post_data(FCGX_Request *request, std::string &data)
{
    const char *contentLenStr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    int         contentLength = 0;

    if (contentLenStr) {
        contentLength = strtol(contentLenStr, NULL, 10);
    }

    for (int len = 0; len < contentLength; len++) {
        int ch = FCGX_GetChar(request->in);

        if (ch < 0) {

            syslog(LOG_ERR, "Failed to get user information\n");
            return false;

        } else {
            data += ch;
        }
    }

    return true;
}

void simpleWebFactory::handle_request(FCGX_Request *request)
{
    const char *script = FCGX_GetParam("SCRIPT_NAME", request->envp);

    if (strcmp(script, "/login") == 0) {

        hanlde_login_request(request);

    } else if (session_valid(request) || strcmp(script, "/pages/login") == 0) {
        const char *response_content = this->get_html_str(script);

        if (response_content != NULL) {

            FCGX_FPrintF(request->out, "Content-Type: text/html; charset=utf-8\r\n\r\n");
            FCGX_FPrintF(request->out, "%s", response_content);

        } else if ((response_content = this->get_js_str(request)) != NULL) {

            FCGX_FPrintF(request->out, "Cache-Control: no-cache\r\n");
            FCGX_FPrintF(request->out, "Cache-Control: no-store\r\n");
            FCGX_FPrintF(request->out, "Content-Type: application/json; charset=utf-8\r\n\r\n");
            FCGX_FPrintF(request->out, "%s", response_content);

        } else {
            FCGX_FPrintF(request->out, "HTTP/1.1 404 Not Found\r\n\r\n");
        }
    } else {
        redirect(request, "/pages/login");
    }

}

const char* simpleWebFactory::get_html_str(const char * url)
{
    const char* main_content = NULL;
    std::map<std::string, std::string>::iterator it;

    it = this->url_html_map.find(url);
    if (it == this->url_html_map.end()) {
        return NULL;
    }

    main_content = it->second.c_str();

    std::ostringstream ss_html;

    ss_html <<  "<!doctype html>\n"
                "<html lang=\"en\">\n";
    ss_html << this->html_header_str;

    ss_html << "<body>\n";

    if (it->first.compare("/pages/login") != 0) {
        ss_html << this->html_navbar_str;
    }

    // container begin
    ss_html << "<div class=\"container-fluid\"><div class=\"row\">\n";

    ss_html <<"   <main role=\"main\" class=\"col-md-12 ml-sm-auto col-lg-12 pt-3 px-4\">\n";
    ss_html << main_content;
    ss_html << "   </main>\n";

    ss_html << "</div";
    // container end

    ss_html << this->html_footer_str;

    ss_html << "</body>\n";
    ss_html << "</html>\n";

    static std::string html;

    html = ss_html.str();

    return html.c_str();
}

const char* simpleWebFactory::get_js_str(FCGX_Request *request)
{
    std::map<std::string,jsCallback>::iterator it;

    it = this->url_js_map.find(FCGX_GetParam("SCRIPT_NAME", request->envp));
    if (it == this->url_js_map.end()) {
        return NULL;
    }

    static std::string js;

    js = it->second(request);

    return js.c_str();
}
