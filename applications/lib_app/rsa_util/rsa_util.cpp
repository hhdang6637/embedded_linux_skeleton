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

#define OPENSSL_CA_CONFIG "/CA.cnf"
#define OPENSSL_CERTS_DIR "/certs"
#define OPENSSL_KEYS_DIR "/keys"
#define OPENSSL_REQS_DIR "/reqs"
#define OPENSSL_INDEX_FILE "/index.txt"
#define OPENSSL_SERIAL_FILE "/serial"


static int openssl_rsa_system(const char *cmd)
{
    // we need this wrapper to replace system by
    // another function in the future
    return system(cmd);
}

bool openssl_ca_init(const char* openssl_ca_dir)
{
    int rc;
    char cmd_gen_index_file[256];
    char cmd_gen_serial_file[256];
    char openssl_ca_config[256];
    char openssl_keys_dir[256];
    char openssl_certs_dir[256];
    char openssl_index_file[256];
    char openssl_serial_file[256];
    char openssl_reqs_dir[256];

    snprintf(openssl_ca_config, sizeof(openssl_ca_config), "%s%s",openssl_ca_dir, OPENSSL_CA_CONFIG);

    std::ofstream ca_confg_file(openssl_ca_config);

    if(ca_confg_file.is_open()) {
        ca_confg_file <<   "[ ca ]\n"
                            "default_ca      = local_ca\n"
                            "[ local_ca ]\n"
                            "dir             = " << openssl_ca_dir << "\n"
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
    }

    mkdir(openssl_ca_dir, 0755);

    snprintf(openssl_certs_dir, sizeof(openssl_certs_dir), "%s%s",openssl_ca_dir, OPENSSL_CERTS_DIR);
    mkdir(openssl_certs_dir, 0755);

    snprintf(openssl_reqs_dir, sizeof(openssl_reqs_dir),"%s%s", openssl_ca_dir, OPENSSL_REQS_DIR);
    mkdir(openssl_reqs_dir,0755);

    snprintf(openssl_keys_dir, sizeof(openssl_keys_dir), "%s%s",openssl_ca_dir,OPENSSL_KEYS_DIR);
    mkdir(openssl_keys_dir, 0755);

    snprintf(openssl_index_file, sizeof(openssl_index_file),"%s%s",openssl_ca_dir, OPENSSL_INDEX_FILE);
    snprintf(cmd_gen_index_file,  sizeof(cmd_gen_index_file),
        "touch %s", openssl_index_file);

    snprintf(openssl_serial_file, sizeof(openssl_serial_file),"%s%s", openssl_ca_dir,OPENSSL_SERIAL_FILE);
    snprintf(cmd_gen_serial_file, sizeof(cmd_gen_serial_file),
        "echo 01 >> %s", openssl_serial_file);

    rc = openssl_rsa_system(cmd_gen_index_file);
    syslog(LOG_INFO, "openssl_ca_init:cmd_gen_index_file: %s return %d\n",
        cmd_gen_index_file, rc);

    if(rc != 0)
        return false;

    rc = openssl_rsa_system(cmd_gen_serial_file);
    syslog(LOG_INFO, "openssl_ca_init:cmd_gen_serial_file: %s return %d\n",
        cmd_gen_serial_file, rc);
    if(rc != 0)
        return false;

    return true;
}

bool openssl_req(const char *dst_key, const char* dst_csr, int days, int bitSize, char* subject)
{
    // ex: openssl req -nodes -newkey rsa:1024 -keyout /tmp/myCA/keys/server.pem -days 365 -keyform PEM -out /tmp/myCA/reqs/server.pem -outform PEM
    //-subj "/C=VN/ST=HCM/L=HCM/O=Example Security/OU=IT Department/CN=example.com/emailAddress=server@gmail.com"

    int rc;
    char cmd_openssl_gen_req[256];

    snprintf(cmd_openssl_gen_req, sizeof(cmd_openssl_gen_req),
        "openssl req  -newkey rsa:%d -keyout %s -days %d -keyform PEM -out %s -outform PEM -subj \" %s \"",
        bitSize, dst_key, days, dst_csr, subject);

    rc = openssl_rsa_system(cmd_openssl_gen_req);
    syslog(LOG_INFO, "openssl_req: %s return %d\n", cmd_openssl_gen_req, rc);

    if(rc == 0) {
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

    snprintf(openssl_ca_config, sizeof(openssl_ca_config), "%s%s", openssl_ca_dir, OPENSSL_CA_CONFIG);

    snprintf(cmd_openssl_gen_rsa_key, sizeof(cmd_openssl_gen_rsa_key),
        "openssl genrsa -out %s %d", ca_key, bitSize);

    rc = openssl_rsa_system(cmd_openssl_gen_rsa_key);

    syslog(LOG_INFO, "openssl_gen_ca_key: %s return %d\n",
        cmd_openssl_gen_rsa_key, rc);

    if(rc == 0) {
        char cmd_gen_ca_cert[256];
        snprintf(cmd_gen_ca_cert, sizeof(cmd_gen_ca_cert),
            "openssl req -config %s -new -x509 -days %d -key %s -out %s -outform PEM",
            openssl_ca_config ,days, ca_key, ca_crt);

        rc = openssl_rsa_system(cmd_gen_ca_cert);
        syslog(LOG_INFO, "openssl_gen_ca_cert: %s return %d\n",
            cmd_gen_ca_cert, rc);

        if(rc == 0) {
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
    snprintf(openssl_ca_config, sizeof(openssl_ca_config),"%s%s" ,openssl_ca_dir, OPENSSL_CA_CONFIG);

    snprintf(cmd_sign_req, sizeof(cmd_sign_req),
        "yes | openssl ca -config %s -in %s -days %d -out %s",
        openssl_ca_config, src_csr, days, dst_crt);

    rc = openssl_rsa_system(cmd_sign_req);
    syslog(LOG_INFO, "openssl_sign: %s return %d\n", cmd_sign_req, rc);

    if(rc == 0)
    {
        return true;
    }

    return false;
}

bool openssl_gen_dh(const char* dh_key, int bitsize)
{
    int rc;
    char cmd_gen_dh[256];
    snprintf(cmd_gen_dh, sizeof(cmd_gen_dh), "openssl dhparam -out %s %d", dh_key, bitsize);

    rc =  openssl_rsa_system(cmd_gen_dh);

    syslog(LOG_INFO, "openssl_gen_dh: %s return %d\n", cmd_gen_dh, rc);

    if( rc == 0) {
        return true;
    } else {
        return false;
    }
}
