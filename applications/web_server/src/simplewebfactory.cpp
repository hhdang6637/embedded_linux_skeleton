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

void simpleWebFactory::redirect(FCGX_Request *request, std::string url_redirect)
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

void simpleWebFactory::login_header_reponse(FCGX_Request *request, bool validate_login)
{
    if (validate_login)
    {
        const char *response_content = this->get_html_str("/pages/home");

        FCGX_FPrintF(request->out, "HTTP/1.1 301 Moved Permanently\r\n");
        FCGX_FPrintF(request->out, "Location: /pages/home\r\n");

        FCGX_FPrintF(request->out, "Content-Type: text/html; charset=utf-8\r\n\r\n");

        FCGX_FPrintF(request->out, "%s", response_content);
    } else {
        redirect(request, "/pages/login");
    }
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
    // TODO: skip validation for JS and CSS request

    // TODO: check session is valid
    bool session_valid = true;
    bool validate_login = true;

    const char *script = FCGX_GetParam("SCRIPT_NAME", request->envp);

    if (strcmp(script, "/login") == 0)
    {
        const char *method = FCGX_GetParam("REQUEST_METHOD", request->envp);
        const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);

        if (method && (strcmp(method, "POST") == 0)) {
            std::string data;

            if (get_post_data(request, data)) {

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

                if (username.compare("admin") == 0 && password.compare("admin") == 0)
                {
                    login_header_reponse(request, validate_login);
                } else
                {
                    validate_login = false;
                    login_header_reponse(request, validate_login);
                }
            }
        }

    } else if (session_valid || strcmp(script, "/pages/login") == 0) {
        const char *response_content = this->get_html_str(script);

        if (response_content != NULL) {

            FCGX_FPrintF(request->out, "Content-Type: text/html; charset=utf-8\r\n\r\n");
            FCGX_FPrintF(request->out, "%s", response_content);

        } else if ((response_content = this->get_js_str(request)) != NULL) {

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
