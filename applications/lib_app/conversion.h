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

#define EVENT_CPU_TEMP 0x01

std::list<std::string> event2Strings(const uint16_t events);

#endif /* APPLICATIONS_LIB_APP_CONVERSION_H_ */
