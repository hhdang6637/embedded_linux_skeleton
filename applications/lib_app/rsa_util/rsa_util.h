/*
 * rsa_util.h.h
 *
 *  Created on: Jan 17, 2019
 *      Author: hhdang6637
 */

#ifndef _RSA_UTIL_H_
#define _RSA_UTIL_H_

bool openssl_ca_init(void);
bool openssl_req(const char *dst_key, const char* dst_csr, int days, int bitSize, char* subject);
bool openssl_gen_ca(const char* ca_key, const char* ca_crt, int days, int bitsize);
bool openssl_sign(const char* src_csr, const char* dst_crt, int days);
bool openssl_gen_dh(const char* dh_key, int bitsize);

#endif // _RSA_UTIL_H_
