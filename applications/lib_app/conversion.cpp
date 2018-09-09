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

std::string time2String(const time_t &time)
{
    struct tm * p = localtime(&time);
    char timeStr[48];
    strftime(timeStr, 48, "%A, %B %d %H:%M:%S %Y", p);

    return std::string(timeStr);
}
