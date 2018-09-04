/*
 * conversion.cpp
 *
 *  Created on: Aug 30, 2018
 *      Author: nmhien
 */
#include "conversion.h"

std::list<std::string> event2Strings(const uint16_t events)
{
    std::list<std::string> strings;

    if (events & EVENT_CPU_TEMP) {
        strings.push_back(std::string("CPU temperature threshold exceed"));
    }

    return strings;
}
