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

#ifdef ENABLE_CHALLENGE

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include "global.h"
#include "session.h"
#include "libstr.h"
#include "challenge.h"
#include "mbedtls/sha256.h"
#include "send.h"

#define COOKIE_SIZE 20
#define SECRET_SIZE 20

extern char *hs_conlen;
extern char *hs_lctn;

static char *cookie_name = "HiawathaClientChallenge";
static size_t cookie_name_len;
static char secret[SECRET_SIZE];

static int get_random(char *buffer, size_t size) {
	int fp, result = 0;

	if ((fp = open("/dev/urandom", O_RDONLY)) == -1) {
		return -1;
	}

	if (read(fp, buffer, size) == -1) {
		result = -1;
	}

	close(fp);

	return result;
}

int init_challenge_module(char *challenge_secret) {
	size_t len;

	cookie_name_len = strlen(cookie_name);

	if (challenge_secret == NULL) {
		if (get_random((char*)&secret, SECRET_SIZE) != 0) {
			return -1;
		}
	} else {
		if ((len = strlen(challenge_secret)) > SECRET_SIZE) {
			len = SECRET_SIZE;
		}

		memset(secret, 0, SECRET_SIZE);
		memcpy(secret, challenge_secret, len);
	}

	return 0;
}

static int generate_cookie(t_session *session, char *cookie, size_t size) {
	char text[MAX_IP_STR_LEN + SECRET_SIZE + 1];
	unsigned char bin_hash[32];
	char hex_hash[65];
	size_t len;

	if (size - 1 > 64) {
		return -1;
	}

	ip_to_str(&(session->ip_address), text, 99);
	len = strlen(text);
	memcpy(text + len, secret, SECRET_SIZE);
	*(text + len + SECRET_SIZE) = '\0';
	mbedtls_sha256((unsigned char*)text, len + SECRET_SIZE, bin_hash, 0);
	sha256_bin2hex(bin_hash, hex_hash);

	memcpy(cookie, hex_hash, size - 1);
	*(cookie + size - 1) = '\0';

	return 0;
}

static int get_cookie(t_session *session, char *cookie, size_t size) {
	char *rest, *key, *value, *header;

	if ((header = get_http_header("Cookie:", session->http_headers)) == NULL) {
		return -1;
	}

	if ((header = strdup(header)) == NULL) {
		return -1;
	}
	rest = header;

	do {
		split_string(rest, &value, &rest, ';');

		if (split_string(value, &key, &value, '=') == -1) {
			continue;
		} else if (strcmp(key, cookie_name) != 0) {
			continue;
		}

		if (strlen(value) >= size) {
			break;
		}
		strcpy(cookie, value);

		free(header);

		return 0;
	} while (rest != NULL);

	free(header);

	return -1;
}

static int send_cookie_head(t_session *session) {
	if (send_header(session) == -1) {
		return -1;
	}

	if (send_buffer(session, "Cache-Control: no-store, no-cache, must-revalidate\r\n", 52) == -1) {
		return -1;
	} else if (send_buffer(session, "Pragma: no-cache\r\n", 18) == -1) {
		return -1;
	}

	return 0;
}

static int send_cookie_tail(t_session *session, int content_length) {
	char conlen[10];

	if (content_length > 99999) {
		return -1;
	}

	sprintf(conlen, "%d\r\n\r\n", content_length);

	if (send_buffer(session, hs_conlen, 16) == -1) {
		return -1;
	} else if (send_buffer(session, conlen, strlen(conlen)) == -1) {
		return -1;
	}

	return 0;
}

static int send_cookie_as_httpheader(t_session *session, char *cookie, size_t cookie_len) {
	session->return_code = 307;

	if (send_cookie_head(session) == -1) {
		return -1;
	}

	if (send_buffer(session, hs_lctn, 10) == -1) {
		return -1;
	} else if (send_buffer(session, session->request_uri, strlen(session->request_uri)) == -1) {
		return -1;
	} else if (send_buffer(session, "\r\n", 2) == -1) {
		return -1;
	}

	if (send_buffer(session, "Set-Cookie: ", 12) == -1) {
		return -1;
	} else if (send_buffer(session, cookie_name, cookie_name_len) == -1) {
		return -1;
	} else if (send_buffer(session, "=", 1) == -1) {
		return -1;
	} else if (send_buffer(session, cookie, cookie_len) == -1) {
		return -1;
	} else if (send_buffer(session, "\r\n", 2) == -1) {
		return -1;
	}

	if (send_cookie_tail(session, 0) == -1) {
		return -1;
	}

	return 0;
}

static int send_cookie_as_javascript(t_session *session, char *cookie, size_t cookie_len) {
	size_t uri_len;

	uri_len = strlen(session->request_uri);

	if (send_cookie_head(session) == -1) {
		return -1;
	}

	if (send_cookie_tail(session, 111 + cookie_name_len + cookie_len + uri_len) == -1) {
		return -1;
	}

	if (send_buffer(session, "<html><head><script type=\"text/javascript\">\n", 44) == -1) {
		return -1;
	} else if (send_buffer(session, "document.cookie='", 17) == -1) {
		return -1;
	} else if (send_buffer(session, cookie_name, cookie_name_len) == -1) {
		return -1;
	} else if (send_buffer(session, "=", 1) == -1) {
		return -1;
	} else if (send_buffer(session, cookie, cookie_len) == -1) {
		return -1;
	} else if (send_buffer(session, "';\n", 3) == -1) {
		return -1;
	} else if (send_buffer(session, "document.location='", 19) == -1) {
		return -1;
	} else if (send_buffer(session, session->request_uri, uri_len) == -1) {
		return -1;
	} else if (send_buffer(session, "';\n", 3) == -1) {
		return -1;
	} else if (send_buffer(session, "</script></head></html>\n", 24) == -1) {
		return -1;
	}

	return 0;
}

int challenge_client(t_session *session) {
	char generated[COOKIE_SIZE + 1];
	char collected[COOKIE_SIZE + 1];

	if (generate_cookie(session, (char*)&generated, COOKIE_SIZE + 1) == -1) {
		return 500;
	}

	if (get_cookie(session, (char*)&collected, COOKIE_SIZE + 1) == -1) {
		if (session->kept_alive > 1) {
			return 503;
		}

		if (session->config->challenge_mode == cm_httpheader) {
			if (send_cookie_as_httpheader(session, generated, COOKIE_SIZE) == -1) {
				return -1;
			}
		} else if (session->config->challenge_mode == cm_javascript) {
			if (send_cookie_as_javascript(session, generated, COOKIE_SIZE) == -1) {
				return -1;
			}
		} else {
			return 500;
		}

		return 200;
	}

	return strcmp_rtap(generated, collected) == 0 ? 0 : 503;
}

#endif
