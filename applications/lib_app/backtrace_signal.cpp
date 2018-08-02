/*
 * backtrace.cpp
 *
 *  Created on: Aug 1, 2018
 *      Author: nmhien
 */
#include <execinfo.h>
#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "backtrace_signal.h"

#define BT_BUF_SIZE 100

static void backtrace_print_to_syslog()
{
    void *buffer[BT_BUF_SIZE];
    char **strings;
    int  nptrs;

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    strings = backtrace_symbols(buffer, nptrs);

    /* skip first stack frame (points here) */
    for (int i = 1; i < nptrs && strings != NULL; ++i) {
        syslog(LOG_ERR, "[bt]: (%d) %s\n", i, strings[i]);
    }

    free(strings);
}

static void backtrace_signal_handler(int sig, siginfo_t *siginfo, void *ctx)
{
    FILE  *fp;
    pid_t pid;
    char  tmp[64];
    char  cmd[64];

    // get the program cmdline
    pid = getpid();
    sprintf(tmp, "/proc/%d/cmdline", pid);
    if ((fp = fopen(tmp, "r")) != NULL) {
        fgets(cmd, sizeof(cmd), fp);
        fclose(fp);
    }

    syslog(LOG_ERR, "\n%s received signal %d (%s)\n", cmd, sig, strsignal(sig));

    backtrace_print_to_syslog();

    exit(EXIT_FAILURE);
}

void backtrace_init_signal()
{
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    sa.sa_sigaction = backtrace_signal_handler;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}
