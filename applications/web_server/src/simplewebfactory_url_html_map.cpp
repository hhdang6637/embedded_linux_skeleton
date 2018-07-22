/*
 * simplewebfactory_url_html_map.cpp
 *
 *  Created on: Jul 21, 2018
 *      Author: hhdang
 */
#include <syslog.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include "simplewebfactory.h"

void simpleWebFactory::init_url_html_map()
{
    std::ifstream file(INTERNAL_RESOURCE"html_mapping.txt");
    if (file.is_open()) {

        std::string line;

        while (getline(file, line)) {

            std::istringstream sstream(line);
            std::string url;
            std::string file_name;

            if ((getline(sstream, url, ',')) && (getline(sstream, file_name, ','))) {

                std::string html;

                if (file_name[0] != '/') {
                    file_name.insert(0, INTERNAL_RESOURCE);
                }

                if (simpleWebFactory::file_to_string(file_name, html)) {

                    char syslog_message[256];

                    snprintf(syslog_message, 256, "found url:%s map to %s", url.c_str(), file_name.c_str());
                    syslog(LOG_INFO, syslog_message);

                    this->url_html_map.insert(std::pair<std::string, std::string>(url, html));
                }
            }
        }

        file.close();
    }
}
