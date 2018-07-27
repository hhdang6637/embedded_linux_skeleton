/*
 * utilities.h
 *
 *  Created on: Jul 26, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_UTILITIES_H_
#define APPLICATIONS_LIB_APP_UTILITIES_H_

#include <sys/select.h>
#include <list>

void write_pid(const char*pidfile, pid_t pid);
int build_fd_sets(fd_set *read_fds, std::list<int> &fds);

#endif /* APPLICATIONS_LIB_APP_UTILITIES_H_ */
