/*
 * simplewebfactory_url_js_map.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include "simplewebfactory.h"

extern std::string json_cpu_usage_history(const char*url);

void simpleWebFactory::init_url_js_map()
{
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/cpu_usage_history", json_cpu_usage_history));
}
