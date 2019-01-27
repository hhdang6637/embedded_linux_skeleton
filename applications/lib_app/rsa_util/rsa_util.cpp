/*
 * rsa_util.cpp
 *
 *  Created on: Jan 17, 2019
 *      Author: hhdang6637
 */

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

#include <fstream>

#include "rsa_util.h"

#define OPENSSL_CA_CONFIG "CA.cnf"

static int openssl_rsa_system(const char *cmd)
{
    // we need this wrapper to replace system by
    // another function in the future
    return system(cmd);
}

bool openssl_ca_init(const char* openssl_ca_dir)
{
    int rc;
    char tmp_path[256];

    struct stat st;
    if (lstat(openssl_ca_dir, &st) == -1) {
        mkdir(openssl_ca_dir, 0755);
    } else if (!S_ISDIR(st.st_mode)) {
        syslog(LOG_ERR, "openssl_ca_init: %s is not a directory", openssl_ca_dir);
        return false;
    }

    snprintf(tmp_path, sizeof(tmp_path), "%s/%s", openssl_ca_dir, OPENSSL_CA_CONFIG);

    std::ofstream ca_confg_file(tmp_path);

    if (ca_confg_file.is_open()) {
        ca_confg_file <<
                      "dir             = " << openssl_ca_dir << "\n"
                      "[ ca ]\n"
                      "default_ca      = local_ca\n"
                      "[ local_ca ]\n"
                      "certificate     = $dir/certs/ca.crt\n"
                      "database        = $dir/index.txt\n"
                      "new_certs_dir   = $dir/certs\n"
                      "private_key     = $dir/keys/ca.key\n"
                      "serial          = $dir/serial\n"
                      "default_crl_days        = 365\n"
                      "default_days            = 1825\n"
                      "default_md              = sha1\n"
                      "policy          = local_ca_policy\n"
                      "x509_extensions = local_ca_extensions\n"
                      "copy_extensions = copy\n"
                      "[ local_ca_policy ]\n"
                      "commonName              = supplied\n"
                      "stateOrProvinceName     = supplied\n"
                      "countryName             = supplied\n"
                      "emailAddress            = supplied\n"
                      "organizationName        = supplied\n"
                      "organizationalUnitName  = supplied\n"
                      "[ local_ca_extensions ]\n"
                      "basicConstraints        = CA:false\n"
                      "[ req ]\n"
                      "default_bits    = 2048\n"
                      "default_keyfile = $dir/keys/ca.key\n"
                      "default_md      = sha1\n"
                      "prompt                  = no\n"
                      "distinguished_name      = root_ca_distinguished_name\n"
                      "x509_extensions         = root_ca_extensions\n"
                      "[ root_ca_distinguished_name ]\n"
                      "commonName              = MyOwn Root Certificate Authority\n"
                      "stateOrProvinceName     = NC\n"
                      "countryName             = US\n"
                      "emailAddress            = rootCA@gmail.com\n"
                      "organizationName        = CA Authority\n"
                      "organizationalUnitName  = IT Department\n"
                      "[ root_ca_extensions ]\n"
                      "basicConstraints        = CA:true\n"
                      "\n";

        ca_confg_file.close();
    } else {
        syslog(LOG_ERR, "cannot open file %s", tmp_path);
        return false;
    }

    // make keys dir
    snprintf(tmp_path, sizeof(tmp_path), "%s/keys", openssl_ca_dir);
    if (mkdir(tmp_path, 0755) != 0) {
        syslog(LOG_ERR, "cannot create the dir %s", tmp_path);
    }

    // make cert dir
    snprintf(tmp_path, sizeof(tmp_path), "%s/certs", openssl_ca_dir);
    if (mkdir(tmp_path, 0755) != 0) {
        syslog(LOG_ERR, "cannot create the dir %s", tmp_path);
    }

    // make reqs dir
    snprintf(tmp_path, sizeof(tmp_path), "%s/reqs", openssl_ca_dir);
    if (mkdir(tmp_path, 0755) != 0) {
        syslog(LOG_ERR, "cannot create the dir %s", tmp_path);
    }

    snprintf(tmp_path, sizeof(tmp_path), "touch %s/index.txt", openssl_ca_dir);

    rc = openssl_rsa_system(tmp_path);
    syslog(LOG_INFO, "openssl_ca_init: %s return %d\n", tmp_path, rc);
    if (rc != 0) {
        return false;
    }

    snprintf(tmp_path, sizeof(tmp_path), "echo 01 >> %s/serial", openssl_ca_dir);

    rc = openssl_rsa_system(tmp_path);
    syslog(LOG_INFO, "openssl_ca_init: %s return %d\n", tmp_path, rc);
    if (rc != 0) {
        return false;
    }

    return true;
}

bool openssl_client_init(const char* openssl_client_dir)
{
    char tmp_path[256];

    struct stat st;
    if (lstat(openssl_client_dir, &st) == -1) {
        mkdir(openssl_client_dir, 0755);
    } else if (!S_ISDIR(st.st_mode)) {
        syslog(LOG_ERR, "openssl_client_init: %s is not a directory", openssl_client_dir);
        return false;
    }

    // make keys dir
    snprintf(tmp_path, sizeof(tmp_path), "%s/keys", openssl_client_dir);
    if (mkdir(tmp_path, 0755) != 0) {
        syslog(LOG_ERR, "cannot create the dir %s", tmp_path);
    }

    // make cert dir
    snprintf(tmp_path, sizeof(tmp_path), "%s/certs", openssl_client_dir);
    if (mkdir(tmp_path, 0755) != 0) {
        syslog(LOG_ERR, "cannot create the dir %s", tmp_path);
    }

    // make reqs dir
    snprintf(tmp_path, sizeof(tmp_path), "%s/reqs", openssl_client_dir);
    if (mkdir(tmp_path, 0755) != 0) {
        syslog(LOG_ERR, "cannot create the dir %s", tmp_path);
    }

    return true;
}

bool openssl_req(const char *dst_key, const char* dst_csr, int days, int bitSize, char* subject)
{
    // ex: openssl req -nodes -newkey rsa:1024 -keyout /tmp/myCA/keys/server.pem -days 365 -keyform PEM -out /tmp/myCA/reqs/server.pem -outform PEM
    //-subj "/C=VN/ST=HCM/L=HCM/O=Example Security/OU=IT Department/CN=example.com/emailAddress=server@gmail.com"

    int rc;
    char cmd_openssl_gen_req[512];

    snprintf(cmd_openssl_gen_req, sizeof(cmd_openssl_gen_req),
             "openssl req -nodes -newkey rsa:%d -keyout %s -days %d -keyform PEM -out %s -outform PEM -subj \"%s\"",
             bitSize, dst_key, days, dst_csr, subject);

    rc = openssl_rsa_system(cmd_openssl_gen_req);
    syslog(LOG_INFO, "openssl_req: %s return %d\n", cmd_openssl_gen_req, rc);

    if (rc == 0) {
        return true;
    } else {
        return false;
    }
}

bool openssl_gen_ca(const char* openssl_ca_dir, const char* ca_key, const char* ca_crt, int days, int bitSize)
{

    int rc;
    char cmd_openssl_gen_rsa_key[256];
    char openssl_ca_config[256];

    snprintf(openssl_ca_config, sizeof(openssl_ca_config), "%s/%s", openssl_ca_dir, OPENSSL_CA_CONFIG);

    snprintf(cmd_openssl_gen_rsa_key, sizeof(cmd_openssl_gen_rsa_key), "openssl genrsa -out %s %d", ca_key, bitSize);

    rc = openssl_rsa_system(cmd_openssl_gen_rsa_key);

    syslog(LOG_INFO, "openssl_gen_ca_key: %s return %d\n", cmd_openssl_gen_rsa_key, rc);

    if (rc == 0) {
        char cmd_gen_ca_cert[256];
        snprintf(cmd_gen_ca_cert, sizeof(cmd_gen_ca_cert),
                 "openssl req -config %s -new -x509 -days %d -key %s -out %s -outform PEM", openssl_ca_config, days,
                 ca_key, ca_crt);

        rc = openssl_rsa_system(cmd_gen_ca_cert);
        syslog(LOG_INFO, "openssl_gen_ca_cert: %s return %d\n", cmd_gen_ca_cert, rc);

        if (rc == 0) {
            return true;
        } else {
            return false;
        }

    } else {
        return false;
    }
}

bool openssl_sign(const char* openssl_ca_dir, const char* src_csr, const char* dst_crt, int days)
{
    // ex: openssl ca -config configCA.cnf -in req/server.csr -out cert/server.crt
    int rc;
    char cmd_sign_req[256];
    char openssl_ca_config[256];
    snprintf(openssl_ca_config, sizeof(openssl_ca_config), "%s/%s", openssl_ca_dir, OPENSSL_CA_CONFIG);

    snprintf(cmd_sign_req, sizeof(cmd_sign_req), "yes | openssl ca -config %s -in %s -days %d -out %s",
             openssl_ca_config, src_csr, days, dst_crt);

    rc = openssl_rsa_system(cmd_sign_req);
    syslog(LOG_INFO, "openssl_sign: %s return %d\n", cmd_sign_req, rc);

    if (rc == 0) {
        return true;
    }

    return false;
}

bool openssl_gen_dh(const char* dh_key, int bitsize)
{
#if 0
    int rc;
    char cmd_gen_dh[256];
    snprintf(cmd_gen_dh, sizeof(cmd_gen_dh), "openssl dhparam -out %s %d", dh_key, bitsize);

    rc = openssl_rsa_system(cmd_gen_dh);

    syslog(LOG_INFO, "openssl_gen_dh: %s return %d\n", cmd_gen_dh, rc);

    if (rc == 0) {
        return true;
    } else {
        return false;
    }
#else
    std::ofstream dh_file(dh_key);

    if (dh_file.is_open()) {
        dh_file <<
"-----BEGIN DH PARAMETERS-----\n"
"MIICCAKCAgEA22vBE1bv+y2zWLe3uKAMNU5ZC9ft+0QcHwM1fDW1Bszy9Hop0zft\n"
"11QzCNPacONPxHihTsbikfjjxkJQ+8L/k4MBPN91nuigSO6X6Gnccq7rxwHcv+UG\n"
"MZFmXekPbLkmS9/xo484yglrgzi7JrznsO8zibq6bPG4ApZqQC1DfBUKADUKjSNZ\n"
"5aqiAWMoUduW+lAc6JTnVxeeNV/0BXDjlAbPj5tURC0JYUe9+rMa5lerOPjD7c/2\n"
"h/hfEaB0xgiqqq9RDucZloJJadz6OEdkYxgsLR8VH88seEa95TLFCNJ7A02w2GtM\n"
"SIevgdtxsdFURRLqbtZuYs9qFlHSfLBJeI0Qn/3oqKKzkDliZWxzQgKVcppFWtvB\n"
"KomAUyY2sEw8P75FEMqIUY3n05N+4Iy+GihivAL9SQJTxqOip8lr80f+4wyi4Zt/\n"
"GNUm+c3/E7eup7W/FSepD0oIDrLZw25yrmWa2ZNPpGW8xLr/Vl5rnjvEaVIu2Gb4\n"
"1yBc7aUBSHBr43JkZO4WafQ4zreQwzDw5yT/8C1cP/aCb2uBRERq47+ZLQwNIwEV\n"
"OopGQg3NwztkGOjarDgc5zeo7OPfFW/4f9zhNoTapVT99blVRS1wofGzIbE6/V8T\n"
"z33ZPgMLRlc/G1a2hRgfa5hXGAN9T+206TIe5tx84qy7ZHH0RuwvzUMCAQI=\n"
"-----END DH PARAMETERS-----\n"
                      "\n";

        dh_file.close();
    } else {
        syslog(LOG_ERR, "cannot open file %s", dh_key);
        return false;
    }

    return true;
#endif
}

bool openssl_get_subject_crt(const char *server_crt_path, char *server_subject, size_t size_name)
{
    char line[256];
    char cmd_str[256];

    snprintf(cmd_str, sizeof(cmd_str), "openssl x509 -noout -subject -in %s 2>/dev/null", server_crt_path);

    FILE *f = popen(cmd_str, "r");
    if (f == NULL) {
        syslog(LOG_ERR, "cannot run command : %s", cmd_str);
        return false;
    }

    if (fgets(line, sizeof(line), f) > 0) {

        if (line[strlen(line) -1] == '\n') {
            line[strlen(line) -1] = '\0'; // remove the \n character
        }

        if (strlen(line) <= size_name) {
            snprintf(server_subject, size_name, "%s", line);
        }
    }

    pclose(f);

    return true;
}
