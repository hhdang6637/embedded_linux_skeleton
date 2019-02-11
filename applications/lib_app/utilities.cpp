/*
 * utilities.cpp
 *
 *  Created on: Jul 26, 2018
 *      Author: hhdang
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <algorithm>

#include "utilities.h"

#define BUF_SIZE 1024

void write_pid(const char*pidfile, pid_t pid)
{
    FILE *fp;

    if ((fp = fopen(pidfile, "w")) == NULL) {
        fprintf(stderr, "Warning: can't write PID file %s.\n", pidfile);
        return;
    }

    fprintf(fp, "%d\n", (int)pid);
    fclose(fp);

    if (chmod(pidfile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
        fprintf(stderr, "Warning: can't chmod PID file %s. Make sure it's only writable for root!\n", pidfile);
    }
}

pid_t get_pid_from_pidfile(const char *pidfile)
{
    FILE *fp;
    pid_t pid;

    if ((fp = fopen(pidfile, "r")) == NULL) {
        fprintf(stderr, "Warning: can't read PID file %s.\n", pidfile);
        return -1;
    }

    fscanf(fp, "%d", (int*)&pid);
    fclose(fp);

    return pid;
}

bool copy_file(const char *src, const char*dst)
{
    int     src_fd, dst_fd;
    ssize_t num_read;
    char    buf[BUF_SIZE];
    bool    rc = true;

    src_fd = open(src, O_RDONLY);

    dst_fd = creat(dst, S_IRUSR | S_IWUSR);

    if (src_fd != -1 && dst_fd != -1) {
        while ((num_read = ::read(src_fd, buf, BUF_SIZE)) > 0) {

            if (::write(dst_fd, buf, num_read) != num_read) {
                syslog(LOG_ERR, "%s-%d: couldn't write whole buffer\n", __FUNCTION__, __LINE__);
                rc = false;
                goto out;
            }

        }

        if (num_read == -1) {
            syslog(LOG_ERR, "%s-%d: read failed\n", __FUNCTION__, __LINE__);
            rc = false;
            goto out;
        }
    }

out:
    if (src_fd != -1) {
        close(src_fd);
    } else {
        syslog(LOG_ERR, "%s-%d: couldn't open file %s\n", __FUNCTION__, __LINE__, src);
    }

    if (dst_fd != -1) {
        close(dst_fd);
    } else {
        syslog(LOG_ERR, "%s-%d: couldn't open file %s\n", __FUNCTION__, __LINE__, dst);
    }

    return rc;
}

int build_fd_sets(fd_set *read_fds, std::list<int> &fds)
{
    int max = 0;
    FD_ZERO(read_fds);

    for (auto &i : fds) {
        FD_SET(i, read_fds);
        if (max < i) {
            max = i;
        }
    }

    return max;
}

void *file_to_addr(const char*file_name, long int *st_size)
{
    struct stat sbuf;
    void *addr = NULL;
    int ifd = ::open(file_name, O_RDONLY);

    if (ifd < 0) {
        syslog(LOG_INFO, "Can't open %s: %s\n", file_name, strerror(errno));
        goto out;
    }

    if (::fstat(ifd, &sbuf) < 0) {
        syslog(LOG_INFO, "Can't stat %s: %s\n", file_name, strerror(errno));
        goto out;
    }

    addr = ::mmap(0, sbuf.st_size, PROT_READ, MAP_SHARED, ifd, 0);
    if (addr == MAP_FAILED) {
        syslog(LOG_INFO, "Can't read %s: %s\n", file_name, strerror(errno));
        addr = NULL;
        goto out;
    }

    *st_size = sbuf.st_size;

out:
    if (ifd != -1) {
        close (ifd);
    }

    return addr;
}

void string_copy(char *dst, const std::string &src, size_t len)
{
    strncpy(dst, src.c_str(), len);
    dst[len-1] = '\0';
}

void string_remove_spaces(std::string &str)
{
    str.erase(std::remove_if(str.begin(), str.end(), [](unsigned char x) {return std::isspace(x);}),
              str.end());
}
