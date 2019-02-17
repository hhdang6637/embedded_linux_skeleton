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

std::string ASN1_to_string(const char *szYYMMDDHHMMSS)
{
    struct tm Tm = {};

    if (sscanf(szYYMMDDHHMMSS, "%2d%2d%2d%2d%2d%2dZ",
               &Tm.tm_year,
               &Tm.tm_mon,
               &Tm.tm_mday,
               &Tm.tm_hour,
               &Tm.tm_min,
               &Tm.tm_sec) != 6) {
        return "";
    }

    Tm.tm_mon -= 1; // Because of tm_mon: 0-11

    // hack, struct tm start 1900
    Tm.tm_year += 100;

    return time2String(mktime(&Tm));
}
