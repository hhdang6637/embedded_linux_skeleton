/*
 * conversion.h
 *
 *  Created on: Aug 30, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_LIB_APP_CONVERSION_H_
#define APPLICATIONS_LIB_APP_CONVERSION_H_

#include <stdint.h>
#include <list>
#include <string>

#include "rpcMessageUsers.h"

#define EVENT_CPU_TEMP 0x01

std::list<std::string> event2Strings(const uint16_t events);
std::string time2String(const time_t &time);

std::string userMsgResult2Str(const app::rpcMessageUsersResultType type);

#endif /* APPLICATIONS_LIB_APP_CONVERSION_H_ */
