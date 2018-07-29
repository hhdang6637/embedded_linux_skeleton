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

#define uswap_32(x) \
    ((((x) & 0xff000000) >> 24) | \
     (((x) & 0x00ff0000) >>  8) | \
     (((x) & 0x0000ff00) <<  8) | \
     (((x) & 0x000000ff) << 24))

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define be32_to_cpu(x)     uswap_32(x)
#else
# define be32_to_cpu(x)     (x)
#endif

void write_pid(const char*pidfile, pid_t pid);
int build_fd_sets(fd_set *read_fds, std::list<int> &fds);
bool copy_file(const char *src, const char*dst);
void *file_to_addr(const char*file_name);

#endif /* APPLICATIONS_LIB_APP_UTILITIES_H_ */
