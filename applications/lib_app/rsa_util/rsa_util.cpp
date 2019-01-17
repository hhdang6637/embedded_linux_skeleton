/*
 * rsa_util.cpp
 *
 *  Created on: Jan 17, 2019
 *      Author: hhdang6637
 */

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>

#include "rsa_util.h"

static int openssl_rsa_system(const char *cmd) {
    // we need this wrapper to replace system by
    // another function in the future
    return system(cmd);
}

bool openssl_gen_rsa(const char *dst_key, int bitsize) {
    // ex: openssl genrsa -des3 -out ca.key 4096
    int rc;
    char cmd_openssl_gen_rsa_key[256];

    snprintf(cmd_openssl_gen_rsa_key, sizeof(cmd_openssl_gen_rsa_key),
        "openssl genrsa -out %s %d", dst_key, bitsize);

    rc = openssl_rsa_system(cmd_openssl_gen_rsa_key);

    syslog(LOG_INFO, "openssl_gen_rsa: %s return %d\n", cmd_openssl_gen_rsa_key, rc);

    if(rc == 0) {
        return true;
    } else {
        return false;
    }
}
