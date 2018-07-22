/*
 * simplewebfactory.cpp
 *
 *  Created on: Jul 20, 2018
 *      Author: hhdang
 */

#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>

#include "simplewebfactory.h"

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

    html_file = INTERNAL_RESOURCE"/menu.html";
    simpleWebFactory::file_to_string(html_file, this->html_menu_str);

    this->init_url_html_map();
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

    ss_html <<  "<!doctype html>"
                "<html lang=\"en\">";
    ss_html << this->html_header_str;

    ss_html << "<body>";
    ss_html << this->html_navbar_str;

    // container begin
    ss_html << "<div class=\"container-fluid\"><div class=\"row\">";

    ss_html << this->html_menu_str;

    ss_html <<"   <main role=\"main\" class=\"col-md-9 ml-sm-auto col-lg-10 pt-3 px-4\">";
    ss_html << main_content;
    ss_html << "   </main>";

    ss_html << "</div";
    // container end

    ss_html << this->html_footer_str;

    ss_html << "</body>";
    ss_html << "</html>";

    static std::string html;

    html = ss_html.str();

    return html.c_str();
}
