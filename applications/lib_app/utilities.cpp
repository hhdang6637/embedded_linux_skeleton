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
