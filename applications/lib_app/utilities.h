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
#include <linux/types.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

void write_pid(const char*pidfile, pid_t pid);
pid_t get_pid_from_pidfile(const char *pidfile);
int build_fd_sets(fd_set *read_fds, std::list<int> &fds);
bool copy_file(const char *src, const char*dst);
void *file_to_addr(const char*file_name, long int *outsize);
void string_copy(char *dst, const std::string &src, size_t len);

#endif /* APPLICATIONS_LIB_APP_UTILITIES_H_ */
