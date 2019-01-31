/*
 * rsa_util.h.h
 *
 *  Created on: Jan 17, 2019
 *      Author: hhdang6637
 */

#ifndef _RSA_UTIL_H_
#define _RSA_UTIL_H_

#include <map>
#include <string>

typedef std::map<std::string, std::string> openssl_subject_t;

bool openssl_ca_init(const char* openssl_ca_dir);
bool openssl_req(const char *dst_key, const char* dst_csr, int days, int bitSize, char* subject);
bool openssl_gen_ca(const char* openssl_ca_dir, const char* ca_key, const char* ca_crt, int days, int bitSize);
bool openssl_sign(const char* openssl_ca_dir, const char* src_csr, const char* dst_crt, int days);
bool openssl_gen_dh(const char* dh_key, int bitsize);
bool openssl_get_subject_crt(const char *server_crt_path, char *server_subject, size_t size_name);
bool openssl_client_init(const char* openssl_client_dir);

openssl_subject_t openssl_subject_parser(const char *subject);

#endif // _RSA_UTIL_H_
