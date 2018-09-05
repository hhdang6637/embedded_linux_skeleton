/*
 * simplewebfactory.cpp
 *
 *  Created on: Jul 20, 2018
 *      Author: hhdang
 */
#include <string.h>

#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>

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

void simpleWebFactory::handle_request(FCGX_Request *request)
{
    const char *response_content = this->get_html_str(FCGX_GetParam("SCRIPT_NAME", request->envp));

    if (response_content != NULL) {

        FCGX_FPrintF(request->out, "Content-Type: text/html; charset=utf-8\r\n\r\n");
        FCGX_FPrintF(request->out, "%s", response_content);

    } else if ((response_content = this->get_js_str(request)) != NULL) {

        FCGX_FPrintF(request->out, "Content-Type: application/json; charset=utf-8\r\n\r\n");
        FCGX_FPrintF(request->out, "%s", response_content);

    } else {
        FCGX_FPrintF(request->out, "HTTP/1.1 404 Not Found\r\n\r\n");
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

    if (it->first.compare("/login") != 0) {
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
