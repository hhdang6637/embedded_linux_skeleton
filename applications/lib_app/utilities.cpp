/*
 * utilities.cpp
 *
 *  Created on: Jul 26, 2018
 *      Author: hhdang
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sendfile.h>

#include "utilities.h"

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

bool copy_file(const char *src, const char*dst)
{
    int src_fd, dst_fd;
    struct stat statbuf;
    bool rc = false;

    src_fd = open(src, O_RDONLY);

    dst_fd = creat(dst, S_IRUSR | S_IWUSR);

    if (src_fd != -1 && dst_fd != -1 && fstat(src_fd, &statbuf) == 0) {
        if (sendfile(dst_fd, src_fd, NULL, statbuf.st_size) == statbuf.st_size) {
            rc = true;
        }
    }

    if (src_fd != -1)
        close(src_fd);

    if (dst_fd != -1)
        close(dst_fd);

    return rc;
}
