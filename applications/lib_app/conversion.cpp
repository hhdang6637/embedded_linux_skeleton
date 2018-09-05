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

std::string userMsgResult2Str(const app::rpcMessageUsersResultType type)
{
    std::string str;
    if (type == app::rpcMessageUsersResultType::SUCCEEDED) {
        str = "succeeded";
    } else if (type == app::rpcMessageUsersResultType::ERROR_MAX_USER) {
        str = "Error max user";
    } else if (type == app::rpcMessageUsersResultType::USER_INVALID) {
        str = "User information not valid";
    } else if (type == app::rpcMessageUsersResultType::USER_NOT_EXISTED) {
        str = "User doesn't exist";
    } else if (type == app::rpcMessageUsersResultType::USERNAME_EXISTED) {
        str = "User name existed";
    } else if (type == app::rpcMessageUsersResultType::EMAIL_EXISTED) {
        str = "Email existed";
    } else if (type == app::rpcMessageUsersResultType::UNKNOWN_ERROR) {
        str = "Unknown error";
    }

    return str;
}
