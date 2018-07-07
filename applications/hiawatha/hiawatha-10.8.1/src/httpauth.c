/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_RPCSVC_CRYPT_H
#include <rpcsvc/crypt.h>
#endif
#include <errno.h>
#include <pthread.h>
#include "libstr.h"
#include "liblist.h"
#include "client.h"
#include "httpauth.h"
#include "monitor.h"
#include "log.h"
#include "mbedtls/base64.h"
#include "mbedtls/md5.h"
#include "memdbg.h"

#define ha_ALLOWED   200
#define ha_DENIED    401
#define ha_FORBIDDEN 403
#define ha_ERROR     500

#ifndef HAVE_CRYPT_R
static pthread_mutex_t crypt_mutex;
#endif

int init_httpauth_module(void) {
#ifndef HAVE_CRYPT_R
	if (pthread_mutex_init(&crypt_mutex, NULL) != 0) {
		return -1;
	}
#endif

	return 0;
}

/* If a required_group_file exist, is a user in the right group?
 */
bool group_oke(t_session *session, char *user, t_charlist *group) {
	bool retval;
	FILE *gfp;
	char line[257], *item, *rest, *result;
	int len;

	if ((user == NULL) || (group->size == 0)) {
		return true;
	}
	if (session->host->groupfile == NULL) {
		return false;
	}

	if ((gfp = fopen_neighbour(session->host->groupfile, "r", session->file_on_disk)) == NULL) {
		switch (errno) {
			case EACCES:
				result = "no access to group file";
				break;
			case ENOENT:
				result = "group file not found";
				break;
			default:
				result = "error while reading group file";
		}
		log_error_file(session, session->host->groupfile, result);
		return false;
	}

	retval = false;
	line[256] = '\0';
	while (fgets(line, 256, gfp) != NULL) {
		if (split_string(line, &item, &rest, ':') == 0) {
			if (in_charlist(item, group)) {
				if ((len = strlen(rest)) == 0) {
					continue;
				}
				if ((rest[len] == '\n') || (rest[len] == '\r')) {
					rest[len] = '\0';
				}
				do {
					split_string(rest, &item, &rest, ' ');
					if (strcmp(user, item) == 0) {
						retval = true;
						break;
					}
				} while (rest != NULL);
			}
		}
		if (retval == true) {
			break;
		}
	}
	fclose(gfp);

	return retval;
}

static FILE *open_password_file(t_session *session) {
	char *result;
	FILE *fp;

	if ((fp = fopen_neighbour(session->host->passwordfile, "r", session->file_on_disk)) == NULL) {
		switch (errno) {
			case EACCES:
				result = "no access to password file";
				break;
			case ENOENT:
				result = "password file not found";
				break;
			default:
				result = "error while reading password file";
		}
		log_error_file(session, session->host->passwordfile, result);
		return NULL;
	}

	return fp;
}

/* Get password from password file
 */
static char *get_password(t_session *session, char *username) {
	char line[257], *result = NULL, *sep;
	FILE *fp;

	if ((fp = open_password_file(session)) == NULL) {
		return NULL;
	}

	line[256] = '\0';
	while ((sep = fgets(line, 256, fp)) != NULL) {
		if ((sep = strchr(sep, ':')) == NULL) {
			continue;
		}

		*(sep++) = '\0';
		if (strcmp(line, username) != 0) {
			continue;
		}

		result = sep;
		while ((*sep != '\n') && (*sep != '\r') && (*sep != ':') && (*sep != '\0')) {
			sep++;
		}
		if (*sep != '\0') {
			*sep = '\0';
			result = strdup(result);
		} else {
			result = NULL;
		}
		break;
	}
	fclose(fp);

	return result;
}

/* Get password (A1) from password file
 */
static char *get_A1(t_session *session, char *username, char *realm) {
	char line[257], *result = NULL, *sep1, *sep2;
	FILE *fp;

	if ((fp = open_password_file(session)) == NULL) {
		return NULL;
	}

	line[256] = '\0';
	while ((sep1 = fgets(line, 256, fp)) != NULL) {
		if ((sep1 = strchr(sep1, ':')) == NULL) {
			continue;
		}

		*(sep1++) = '\0';
		if (strcmp(line, username) != 0) {
			continue;
		}

		if ((sep2 = strchr(sep1, ':')) == NULL) {
			continue;
		}

		*(sep2++) = '\0';
		if (strcmp(sep1, realm) != 0) {
			continue;
		}

		result = sep2;
		while ((*sep2 != '\n') && (*sep2 != '\r') && (*sep2 != ':') && (*sep2 != '\0')) {
			sep2++;
		}
		if (*sep2 != '\0') {
			*sep2 = '\0';
			result = strdup(result);
		} else {
			result = NULL;
		}
		break;
	}
	fclose(fp);

	return result;
}

/* Find algoritm id and salt in password
 */
static int find_algoritm_and_salt(char *line) {
	char *end;

	end = line;
	if (*end != '$') {
		return -1;
	}
	end++;

	if ((*end != '1') && (*end != '5') && (*end != '6')) {
		return -1;
	}
	end++;

	if (*end != '$') {
		return -1;
	}

	if (strcmp(end + 1, "rounds=") == 0) {
		end += 7;
		do {
			end++;
		} while ((*end != '\0') && (*end != '$'));

		if (*end == '\0') {
			return -1;
		}
	}

	do {
		end++;
	} while ((*end != '\0') && (*end != '$'));

	if (*end == '\0') {
		return -1;
	}

	return end - line + 1;
}

/* Basic HTTP authentication.
 */
static int basic_http_authentication(t_session *session, char *auth_str) {
	size_t auth_len;
	int retval, len;
	char *auth_user, *auth_passwd, *passwd, *encrypted, salt[41];
#ifdef HAVE_CRYPT_R
	struct crypt_data crypt_data;
#else
	int cmp_result;
#endif

	auth_len = strlen(auth_str);
	if ((auth_user = (char*)malloc(auth_len + 1)) == NULL) {
		return ha_ERROR;
	}

	/* Decode authentication string
	 */
	if (mbedtls_base64_decode((unsigned char*)auth_user, auth_len, &auth_len, (unsigned char*)auth_str, auth_len) != 0) {
		register_wrong_password(session);
		clear_free(auth_user, auth_len);
		return ha_DENIED;
	}
	*(auth_user + auth_len) = '\0';

	/* Search for password
	 */
	auth_passwd = auth_user;
	while ((*auth_passwd != ':') && (*auth_passwd != '\0')) {
		auth_passwd++;
	}
	if (*auth_passwd != ':') {
		register_wrong_password(session);
		clear_free(auth_user, auth_len);
		return ha_DENIED;
	}
	*(auth_passwd++) = '\0';

	/* Group oke?
	 */
	if (group_oke(session, auth_user, &(session->host->required_group)) == false) {
		clear_free(auth_user, auth_len);
		return ha_FORBIDDEN;
	}

	/* Read password from file
	 */
	if ((passwd = get_password(session, auth_user)) == NULL) {
		register_wrong_password(session);
		clear_free(auth_user, auth_len);
		return ha_DENIED;
	}

	len = find_algoritm_and_salt(passwd);
	if ((len != -1) && (len <= 40)) {
		memcpy(salt, passwd, len);
		salt[len] = '\0';
	} else {
		salt[0] = *passwd;
		salt[1] = *(passwd + 1);
		salt[2] = '\0';
	}

#ifdef HAVE_CRYPT_R
	crypt_data.initialized = 0;
	encrypted = crypt_r(auth_passwd, salt, &crypt_data);

	if (strcmp_rtap(encrypted, passwd) == 0) {
#else
	pthread_mutex_lock(&crypt_mutex);
	encrypted = crypt(auth_passwd, salt);
	cmp_result = strcmp_rtap(encrypted, passwd);
	pthread_mutex_unlock(&crypt_mutex);

	if (cmp_result == 0) {
#endif
		retval = ((session->remote_user = strdup(auth_user)) != NULL) ? ha_ALLOWED : ha_ERROR;
	} else {
		register_wrong_password(session);
		retval = ha_DENIED;
	}

	clear_free(auth_user, auth_len);
	clear_free(passwd, strlen(passwd));

	return retval;
}

static char *unquoted(char *str) {
	int len;

	if (str != NULL) {
		len = strlen(str);
		if (len > 0) {
			if (*str == '\"') {
				str++;
				len--;
			}
			if (str[len - 1] == '\"') {
				str[len - 1] = '\0';
			}
		}
	}

	return str;
}

/* Digest HTTP authentication.
 */
static int digest_http_authentication(t_session *session, char *auth_str) {
	bool quote_found;
	unsigned char digest[16];
	char *key, *value, *rest, *empty = "", *passwd, A1[33], A2[33], result[33];
	char *username = empty, *realm = empty, *nonce = empty, *uri = empty, *response = empty;
	//char *opaque = empty, *algoritm = empty, *cnonce = empty, *nc = empty, *qop = empty;
	size_t len;

	key = rest = auth_str;
	while (*key != '\0') {
		quote_found = false;
		while (*rest != '\0') {
			if (*rest == '"') {
				if (quote_found) {
					if (*(rest + 1) == ',') {
						rest++;
						*(rest++) = '\0';
						break;
					} else if (*(rest + 1) == '\0') {
						rest++;
						break;
					} else {
						return ha_DENIED;
					}
				}
				quote_found = true;
			} else if ((*rest == ',') && (quote_found == false)) {
				*(rest++) = '\0';
				break;
			}
			rest++;
		}

		if (split_string(key, &key, &value, '=') != -1) {
			if (strcmp(key, "username") == 0) {
				username = unquoted(value);
			} else if (strcmp(key, "realm") == 0) {
				realm = unquoted(value);
			} else if (strcmp(key, "nonce") == 0) {
				nonce = unquoted(value);
			} else if (strcmp(key, "uri") == 0) {
				uri = unquoted(value);
			} else if (strcmp(key, "response") == 0) {
				response = unquoted(value);
/*
			} else if (strcmp(key, "opaque") == 0) {
				opaque = unquoted(value);
			} else if (strcmp(key, "algoritm") == 0) {
				algoritm = unquoted(value);
			} else if (strcmp(key, "cnonce") == 0) {
				cnonce = unquoted(value);
			} else if (strcmp(key, "nc") == 0) {
				nc = unquoted(value);
			} else if (strcmp(key, "qop") == 0) {
				qop = unquoted(value);
*/
			}
		}
		key = rest;
	}

	/* Correct URI?
	 */
	if (strcmp(session->request_uri, uri) != 0) {
		return ha_DENIED;
	}

	/* Group oke?
	 */
	if (group_oke(session, username, &(session->host->required_group)) == false) {
		return ha_FORBIDDEN;
	}

	/* Retrieve A1 from passwordfile
	 */
	if ((passwd = get_A1(session, username, realm)) == NULL) {
		register_wrong_password(session);
		return ha_DENIED;
	} else if (strlen(passwd) != 32) {
		clear_free(passwd, strlen(passwd));
		return ha_DENIED;
	}
	memcpy(A1, passwd, 33);
	clear_free(passwd, strlen(passwd));

	/* Calculate A2
	 */
	len = strlen(session->method) + strlen(uri);
	if ((value = (char*)malloc(len + 2)) == NULL) {
		return ha_ERROR;
	}
	sprintf(value, "%s:%s", session->method, uri);
	mbedtls_md5((unsigned char*)value, strlen(value), digest);
	md5_bin2hex(digest, A2);
	clear_free(value, strlen(value));

	/* Calculate response
	 */
	len = strlen(A1) + strlen(nonce) + strlen(A2);
	if ((value = (char*)malloc(len + 3)) == NULL) {
		return ha_ERROR;
	}
	sprintf(value, "%s:%s:%s", A1, nonce, A2);
	mbedtls_md5((unsigned char*)value, strlen(value), digest);
	md5_bin2hex(digest, result);
	clear_free(value, strlen(value));

	/* Password match?
	 */
	if (strcmp_rtap(response, result) != 0) {
		register_wrong_password(session);
		return ha_DENIED;
	}

	return ((session->remote_user = strdup(username)) != NULL) ? ha_ALLOWED : ha_ERROR;
}

/* Check if the file is protected by an .hiawatha file with passwordfile setting.
 */
int http_authentication_result(t_session *session, bool access_on_pwdfile_missing) {
	char *auth_str;
	int result = ha_DENIED;

	if (session->letsencrypt_auth_request) {
		return ha_ALLOWED;
	}

	if (session->host->passwordfile == NULL) {
		return access_on_pwdfile_missing ? ha_ALLOWED : ha_DENIED;
	} else if ((auth_str = get_http_header("Authorization:", session->http_headers)) != NULL) {
		if ((auth_str = strdup(auth_str)) == NULL) {
			return ha_ERROR;
		}

		if ((strncmp(auth_str, "Basic ", 6) == 0) && (session->host->auth_method == basic)) {
			session->http_auth = basic;
			result = basic_http_authentication(session, auth_str + 6);
		} else if ((strncmp(auth_str, "Digest ", 7) == 0) && (session->host->auth_method == digest)) {
			session->http_auth = digest;
			result = digest_http_authentication(session, auth_str + 7);
		}

		if (result == ha_DENIED) {
			sleep(1);
#ifdef ENABLE_MONITOR
			if (session->config->monitor_enabled) {
				monitor_count_failed_login(session);
			}
#endif
		}

		free(auth_str);
	}

	return result;
}
