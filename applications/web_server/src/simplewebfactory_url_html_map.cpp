/*
 * simplewebfactory_url_html_map.cpp
 *
 *  Created on: Jul 21, 2018
 *      Author: hhdang
 */

#include "simplewebfactory.h"

void simpleWebFactory::init_url_html_map()
{
    extern unsigned char _binary_dashboard_html_start[];
    extern unsigned char _binary_dashboard_html_end[];

    char * dashboard_buffer = simpleWebFactory::binary_html_to_chars(_binary_dashboard_html_start, _binary_dashboard_html_end);
    this->url_html_map.insert(std::pair<std::string,std::string>("/", dashboard_buffer));
    delete []dashboard_buffer;
}
