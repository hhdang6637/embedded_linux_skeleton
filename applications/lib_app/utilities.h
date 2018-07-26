/*
 * utilities.h
 *
 *  Created on: Jul 26, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_UTILITIES_H_
#define APPLICATIONS_LIB_APP_UTILITIES_H_

void write_pid(const char*pidfile, pid_t pid);

bool copy_file(const char *src, const char*dst);

#endif /* APPLICATIONS_LIB_APP_UTILITIES_H_ */
