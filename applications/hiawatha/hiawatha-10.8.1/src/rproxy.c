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

#ifdef ENABLE_RPROXY

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include "global.h"
#include "rproxy.h"
#include "tls.h"
#include "ip.h"
#include "libstr.h"
#include "libfs.h"
#include "libstr.h"
#include "mbedtls/md5.h"
#include "memdbg.h"

#define RPROXY_ID_LEN             10 /* Must be smaller than 32 */
#define MAX_SEND_BUFFER            2 * KILOBYTE
#define EXTENSION_SIZE            10
#define SSH_BUFFER                 4 * KILOBYTE
#define UPLOADED_FILE_BUFFER_SIZE  4 * KILOBYTE

static char   *rproxy_header;
static size_t rproxy_header_len;
static char   *rproxy_id_key = "X-Hiawatha-RProxy-ID:";
static char   rproxy_id[33];

extern char *hs_forwarded;
extern char *hs_x_forwarded_for;
extern char *hs_conn;
extern char *hs_concl;

extern char *upgrade_websocket;

typedef struct type_send_buffer {
	char buffer[MAX_SEND_BUFFER];
	int bytes_in_buffer;
} t_send_buffer;

/* Initialize reverse proxy module
 */
int init_rproxy_module(void) {
	unsigned char digest[16];
	char str[50], *format = "%s %s\r\n";
	struct tm s;
	time_t t;
	size_t len;

	time(&t);
	localtime_r(&t, &s);
	strftime(str, 49, "%a %d %b %Y %T", &s);
	str[49] = '\0';

	mbedtls_md5((unsigned char*)str, strlen(str), digest);
	md5_bin2hex(digest, rproxy_id);
	rproxy_id[RPROXY_ID_LEN] = '\0';

	len = strlen(format) - 4 + strlen(rproxy_id_key) + RPROXY_ID_LEN;
	if ((rproxy_header = (char*)malloc(len + 1)) == NULL) {
		return -1;
	}
	sprintf(rproxy_header, format, rproxy_id_key, rproxy_id);
	rproxy_header_len = strlen(rproxy_header);

	return 0;
}

/* Parse configuration line
 */
t_rproxy *rproxy_setting(char *line) {
	t_rproxy *rproxy;
	size_t len;
	char *path, *port, *timeout, *keep_alive;
	int skip_dir;

	if (split_string(line, &path, &line, ' ') != 0) {
		return NULL;
	} else if ((rproxy = (t_rproxy*)malloc(sizeof(t_rproxy))) == NULL) {
		return NULL;
	}

	split_string(line, &line, &timeout, ' ');

	/* Skip directory
	 */
	if ((skip_dir = str_to_int(line)) != -1) {
		split_string(timeout, &line, &timeout, ' ');
	} else {
		skip_dir = 0;
	}

	if (timeout != NULL) {
		split_string(timeout, &timeout, &keep_alive, ' ');
	} else {
		keep_alive = NULL;
	}

	rproxy->next = NULL;
	rproxy->timeout = 5;
	rproxy->keep_alive = false;
	rproxy->skip_dir = skip_dir;

	/* Pattern
	 */
	if (*path == '!') {
		rproxy->neg_match = true;
		path++;
	} else {
		rproxy->neg_match = false;
	}

	if (regcomp(&(rproxy->pattern), path, REG_EXTENDED) != 0) {
		free(rproxy);
		return NULL;
	}

	/* Back connection via Unix socket
	 */
	if (*line == '/') {
		if ((rproxy->unix_socket = strdup(line)) == NULL) {
			check_free(rproxy->path);
			return NULL;
		}

		rproxy->hostname = NULL;
		rproxy->hostname_len = -1;
		rproxy->path = NULL;
		rproxy->path_len = -1;
	} else {
		rproxy->unix_socket = NULL;

		/* Protocol
		 */
		if (strncmp(line, "http://", 7) == 0) {
			line += 7;
#ifdef ENABLE_TLS
			rproxy->use_tls = false;
		} else if (strncmp(line, "https://", 8) == 0) {
			line += 8;
			rproxy->use_tls = true;
#endif
		} else {
			free(rproxy);
			return NULL;
		}

		/* Path
		 */
		rproxy->path = NULL;
		rproxy->path_len = -1;
		if ((path = strchr(line, '/')) != NULL) {
			if ((len = strlen(path)) > 1) {
				if (*(path + len - 1) == '/') {
					*(path + len - 1) = '\0';
				}
				if ((rproxy->path = strdup(path)) == NULL) {
					free(rproxy);
					return NULL;
				}
				rproxy->path_len = strlen(rproxy->path);
			}
			*path = '\0';
		}

		/* Port
		 */
#ifdef ENABLE_IPV6
		if (*line == '[') {
			line++;
			if ((port = strchr(line, ']')) == NULL) {
				check_free(rproxy->path);
				free(rproxy);
				return NULL;
			}
			*(port++) = '\0';
			if (*port == '\0') {
				port = NULL;
			} else if (*port != ':') {
				check_free(rproxy->path);
				free(rproxy);
				return NULL;
			}
		} else
#endif
			port = strchr(line, ':');

		if (port != NULL) {
			*(port++) = '\0';
			if ((rproxy->port = str_to_int(port)) < 1) {
				check_free(rproxy->path);
				free(rproxy);
				return NULL;
			} else if (rproxy->port > 65535) {
				check_free(rproxy->path);
				free(rproxy);
				return NULL;
			}
		} else {
#ifdef ENABLE_TLS
			if (rproxy->use_tls) {
				rproxy->port = 443;
			} else
#endif
				rproxy->port = 80;
		}

		/* Hostname
		 */
		if (parse_ip(line, &(rproxy->ip_addr)) == -1) {
			if ((rproxy->hostname = strdup(line)) == NULL) {
				check_free(rproxy->path);
				free(rproxy);
				return NULL;
			}
			rproxy->hostname_len = strlen(rproxy->hostname);

			if (hostname_to_ip(line, &(rproxy->ip_addr)) == -1) {
				fprintf(stderr, "Can't resolve hostname '%s'\n", line);
				check_free(rproxy->path);
				check_free(rproxy->hostname);
				free(rproxy);
				return NULL;
			}
		} else {
			rproxy->hostname = NULL;
			rproxy->hostname_len = -1;
		}
	}

	/* Timeout
	 */
	if (timeout != NULL) {
		if ((rproxy->timeout = str_to_int(timeout)) <= 0) {
			if (keep_alive != NULL) {
				check_free(rproxy->path);
				check_free(rproxy->hostname);
				free(rproxy);
				return NULL;
			}

			keep_alive = timeout;
		}
	}

	/* Keep-alive
	 */
	if (keep_alive != NULL) {
		if (strcasecmp(keep_alive, "keep-alive") != 0) {
			check_free(rproxy->path);
			check_free(rproxy->hostname);
			free(rproxy);
			return NULL;
		}

		rproxy->keep_alive = true;
	}

	return rproxy;
}

/* Does URL match with proxy match pattern?
 */
t_rproxy *select_rproxy(t_rproxy *rproxy_list, char *uri
#ifdef ENABLE_TLS
		, bool use_tls
#endif
		) {
	t_rproxy *rproxy;

	if ((rproxy_list == NULL) || (uri == NULL)) {
		return false;
	}

#ifdef ENABLE_TLS
	if (rproxy_list->next != NULL) {
		rproxy = rproxy_list;
		while (rproxy != NULL) {
			if (rproxy->use_tls == use_tls) {
				if ((regexec(&(rproxy->pattern), uri, 0, NULL, 0) != REG_NOMATCH) != rproxy->neg_match) {
					return rproxy;
				}
			}

			rproxy = rproxy->next;
		}
	}
#endif

	rproxy = rproxy_list;
	while (rproxy != NULL) {
		if ((regexec(&(rproxy->pattern), uri, 0, NULL, 0) != REG_NOMATCH) != rproxy->neg_match) {
			return rproxy;
		}

		rproxy = rproxy->next;
	}

	return NULL;
}

/* Detect reverse proxy loop
 */
bool rproxy_loop_detected(t_http_header *http_headers) {
	char *value;

	if ((value = get_http_header(rproxy_id_key, http_headers)) == NULL) {
		return false;
	}

	if (strcmp(value, rproxy_id) != 0) {
		return false;
	}

	return true;
}

/* Init reverse proxy result record
 */
void init_rproxy_result(t_rproxy_result *result) {
	result->bytes_sent = 0;
}

/* Send output buffer to webserver
 */
static int send_buffer_to_webserver(t_rproxy_webserver *webserver, const char *buffer, int size) {
#ifdef ENABLE_TLS
	if (webserver->use_tls) {
		return tls_send_buffer(&(webserver->tls_context), buffer, size);
	} else
#endif
		return write_buffer(webserver->socket, buffer, size);
}

/* Send buffer to webserver
 */
static int send_to_webserver(t_rproxy_webserver *webserver, t_rproxy_result *result, t_send_buffer *send_buffer, const char *buffer, int size) {
	if (buffer == NULL) {
		if (send_buffer->bytes_in_buffer > 0) {
			if (send_buffer_to_webserver(webserver, send_buffer->buffer, send_buffer->bytes_in_buffer) == -1) {
				return -1;
			}
		}
	} else if (size > MAX_SEND_BUFFER) {
		if (send_buffer_to_webserver(webserver, send_buffer->buffer, send_buffer->bytes_in_buffer) == -1) {
			return -1;
		}
		send_buffer->bytes_in_buffer = 0;

		if (send_buffer_to_webserver(webserver, buffer, size) == -1) {
			return -1;
		}
	} else if (send_buffer->bytes_in_buffer + size > MAX_SEND_BUFFER) {
		if (send_buffer_to_webserver(webserver, send_buffer->buffer, send_buffer->bytes_in_buffer) == -1) {
			return -1;
		}
		memcpy(send_buffer->buffer, buffer, size);
		send_buffer->bytes_in_buffer = size;
	} else {
		memcpy(send_buffer->buffer + send_buffer->bytes_in_buffer, buffer, size);
		send_buffer->bytes_in_buffer += size;
	}

	result->bytes_sent += size;

	return 0;
}

/* Send the request to the webserver
 */
int send_request_to_webserver(t_rproxy_webserver *webserver, t_rproxy_options *options, t_rproxy *rproxy, t_rproxy_result *result, bool session_keep_alive) {
	t_http_header *http_header;
	char forwarded_for[20 + MAX_IP_STR_LEN], ip_addr[MAX_IP_STR_LEN], forwarded_port[32], *buffer, *referer, *uri;
	bool forwarded_found = false, is_websocket = false, is_referer;
	t_send_buffer send_buffer;
	int handle, bytes_read, skip_dir;
	t_keyvalue *header;
#ifdef ENABLE_CACHE
	char extension[EXTENSION_SIZE];
#endif

	send_buffer.bytes_in_buffer = 0;

	if (ip_to_str(options->client_ip, ip_addr, MAX_IP_STR_LEN) == -1) {
		return -1;
	}

	/* Send first line
	 */
	if (send_to_webserver(webserver, result, &send_buffer, options->method, strlen(options->method)) == -1) {
		return -1;
	} else if (send_to_webserver(webserver, result, &send_buffer, " ", 1) == -1) {
		return -1;
	}

	if (rproxy->path != NULL) {
		if (send_to_webserver(webserver, result, &send_buffer, rproxy->path, rproxy->path_len) == -1) {
			return -1;
		}
	}

	uri = options->uri;
	skip_dir = rproxy->skip_dir;
	while (skip_dir-- > 0) {
		if ((uri = strchr(uri + 1, '/')) == NULL) {
			uri = options->uri;
			break;
		}
	}
	if (send_to_webserver(webserver, result, &send_buffer, uri, strlen(uri)) == -1) {
		return -1;
	}

	if (options->vars != NULL) {
		if (send_to_webserver(webserver, result, &send_buffer, "?", 1) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, options->vars, strlen(options->vars)) == -1) {
			return -1;
		}
	}

	if (send_to_webserver(webserver, result, &send_buffer, " HTTP/1.1\r\n", 11) == -1) {
		return -1;
	}

	/* Search for websocket upgrade
	 */
	for (http_header = options->http_headers; http_header != NULL; http_header = http_header->next) {
		if (strcasecmp(http_header->data, upgrade_websocket) == 0) {
			is_websocket = true;
		}
	}

	if ((rproxy->keep_alive == false) || (session_keep_alive == false) || is_websocket) {
		/* Send Connection: close
		 */
		if (send_to_webserver(webserver, result, &send_buffer, hs_conn, 12) == -1) {
			return -1;
		}

		if (is_websocket) {
			if (send_to_webserver(webserver, result, &send_buffer, "upgrade\r\n", 9) == -1) {
				return -1;
			}
		} else if (send_to_webserver(webserver, result, &send_buffer, hs_concl, 7) == -1) {
			return -1;
		}
	}

	/* Send HTTP headers
	 */
	if (rproxy->hostname != NULL) {
		if (send_to_webserver(webserver, result, &send_buffer, "Host: ", 6) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, rproxy->hostname, rproxy->hostname_len) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, "\r\n", 2) == -1) {
			return -1;
		}
	}

	if (send_to_webserver(webserver, result, &send_buffer, rproxy_header, rproxy_header_len) == -1) {
		return -1;
	}

	for (http_header = options->http_headers; http_header != NULL; http_header = http_header->next) {
		if (rproxy->hostname != NULL) {
			if (strcasecmp(http_header->data, "Expect: 100-Continue") == 0) {
				continue;
			}

			if (strncasecmp(http_header->data, "Host:", 5) == 0) {
				continue;
			}

			is_referer = (strncasecmp(http_header->data, "Origin:", 7) == 0) ||
			             (strncasecmp(http_header->data, "Referer:", 8) == 0);
			if (is_referer && (options->hostname != NULL)) {
				if (str_replace(http_header->data, options->hostname, rproxy->hostname, &referer) > 0) {
					if (send_to_webserver(webserver, result, &send_buffer, referer, strlen(referer)) == -1) {
						free(referer);
						return -1;
					}
					free(referer);
					if (send_to_webserver(webserver, result, &send_buffer, "\r\n", 2) == -1) {
						return -1;
					}

					continue;
				}
			}
		}

		if ((rproxy->keep_alive == false) || (session_keep_alive == false) || is_websocket) {
			if (strncasecmp(http_header->data, hs_conn, 11) == 0) {
				continue;
			}
		}

#ifdef ENABLE_CACHE
		if (strncasecmp(http_header->data, "If-Modified-Since:", 18) == 0) {
			if (extension_from_uri(options->uri, extension, EXTENSION_SIZE)) {
				if (in_charlist(extension, options->cache_extensions)) {
					continue;
				}
			}
		}
#endif

		if (strncasecmp(http_header->data, "X-Forwarded-User:", 17) == 0) {
			continue;
		}


		if (send_to_webserver(webserver, result, &send_buffer, http_header->data, http_header->length) == -1) {
			return -1;
		}

		if (strncasecmp(http_header->data, hs_forwarded, 10) == 0) {
			/* Add IP to Forwarded header
			 */
			if (sprintf(forwarded_for, ", for=\"%s\"\r\n", ip_addr) == -1) {
				return -1;
			} else if (send_to_webserver(webserver, result, &send_buffer, forwarded_for, strlen(forwarded_for)) == -1) {
				return -1;
			}

			forwarded_found = true;
		}

		if (strncasecmp(http_header->data, hs_x_forwarded_for, 16) == 0) {
			/* Add IP to X-Forwarded-For header
			 */

			if (sprintf(forwarded_for, ", %s\r\n", ip_addr) == -1) {
				return -1;
			} else if (send_to_webserver(webserver, result, &send_buffer, forwarded_for, strlen(forwarded_for)) == -1) {
				return -1;
			}

			forwarded_found = true;
		} else if (send_to_webserver(webserver, result, &send_buffer, "\r\n", 2) == -1) {
			return -1;
		}
	}

	/* Send Forwarded and X-Forwarded-For headers
	 */
	if (forwarded_found == false) {
		if (sprintf(forwarded_for, "%s for=\"%s\"\r\n", hs_forwarded, ip_addr) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, forwarded_for, strlen(forwarded_for)) == -1) {
			return -1;
		}

		if (sprintf(forwarded_for, "%s %s\r\n", hs_x_forwarded_for, ip_addr) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, forwarded_for, strlen(forwarded_for)) == -1) {
			return -1;
		}
	}

	/* Send X-Forwared-Proto
	 */
	if (send_to_webserver(webserver, result, &send_buffer, "X-Forwarded-Proto: ", 19) == -1) {
		return -1;
	}
#ifdef ENABLE_TLS
	if (options->use_tls) {
		if (send_to_webserver(webserver, result, &send_buffer, "https\r\n", 7) == -1) {
			return -1;
		}
	} else
#endif
		if (send_to_webserver(webserver, result, &send_buffer, "http\r\n", 6) == -1) {
			return -1;
		}

	/* Send X-Forwarded-Host
	 */
	if (options->hostname != NULL) {
		if (send_to_webserver(webserver, result, &send_buffer, "X-Forwarded-Host: ", 18) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, options->hostname, strlen(options->hostname)) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, "\r\n", 2) == -1) {
			return -1;
		}
	}

	/* Send X-Forwarded-Port
	 */
	snprintf(forwarded_port, 31, "X-Forwarded-Port: %d\r\n", options->port);
	forwarded_port[31] = '\0';
	if (send_to_webserver(webserver, result, &send_buffer, forwarded_port, strlen(forwarded_port)) == -1) {
		return -1;
	}

	/* Send X-Forwarded-User
	 */
	if (options->remote_user != NULL) {
		if (send_to_webserver(webserver, result, &send_buffer, "X-Forwarded-User: ", 18) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, options->remote_user, strlen(options->remote_user)) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, "\r\n", 2) == -1) {
			return -1;
		}
	}

	/* Send custom headers
	 */
	header = options->custom_headers;
	while (header != NULL) {
		if (send_to_webserver(webserver, result, &send_buffer, header->key, strlen(header->key)) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, ": ", 2) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, header->value, strlen(header->value)) == -1) {
			return -1;
		} else if (send_to_webserver(webserver, result, &send_buffer, "\r\n", 2) == -1) {
			return -1;
		}

		header = header->next;
	}

	/* Close header
	 */
	if (send_to_webserver(webserver, result, &send_buffer, "\r\n", 2) == -1) {
		return -1;
	}

	/* Send body
	 */
	if (options->body != NULL) {
		if (send_to_webserver(webserver, result, &send_buffer, options->body, options->content_length) == -1) {
			return -1;
		}
	} else if (options->uploaded_file != NULL) {
		if ((buffer = (char*)malloc(UPLOADED_FILE_BUFFER_SIZE)) != NULL) {
			if ((handle = open(options->uploaded_file, O_RDONLY)) != -1) {
				while ((bytes_read = read(handle, buffer, UPLOADED_FILE_BUFFER_SIZE)) > 0) {
					if (send_to_webserver(webserver, result, &send_buffer, buffer, bytes_read) == -1) {
						break;
					}
				}
				close(handle);
			}
			free(buffer);
		}
	}

	if (send_to_webserver(webserver, result, &send_buffer, NULL, 0) == -1) {
		return -1;
	}

	return 0;
}

static int forward_ssh_data(int from_sock, int to_sock) {
	int bytes_read;
	char buffer[SSH_BUFFER];

	if ((bytes_read = recv(from_sock, buffer, SSH_BUFFER, 0)) <= 0) {
		return -1;
	}

	if (send(to_sock, buffer, bytes_read, 0) == -1) {
		return -1;
	}

	return 0;
}

/* Tunnel CONNECT request to local SSH daemon
 */
int tunnel_ssh_connection(int client_sock) {
	int server_sock;
	t_ip_addr localhost;
	struct pollfd poll_data[2];
	bool quit = false;

	set_to_localhost(&localhost);
	if ((server_sock = connect_to_server(&localhost, 22)) == -1) {
		return -1;
	}

	if (send(client_sock, "HTTP/1.0 200 OK\r\n\r\n", 19, 0) == -1) {
		close(server_sock);
		return -1;
	}

	poll_data[0].fd = client_sock;
	poll_data[0].events = POLL_EVENT_BITS;
	poll_data[1].fd = server_sock;
	poll_data[1].events = POLL_EVENT_BITS;

	while (quit == false) {
		switch (poll(poll_data, 2, 1000)) {
			case -1:
				if (errno != EINTR) {
					quit = true;
				}
				break;
			case 0:
				break;
			default:
				if (poll_data[0].revents != 0) {
					if (forward_ssh_data(client_sock, server_sock) == -1) {
						quit = true;
					}
				}
				if (poll_data[1].revents != 0) {
					if (forward_ssh_data(server_sock, client_sock) == -1) {
						quit = true;
					}
				}
				break;
		}
	}

	close(server_sock);

	return 0;
}

#endif
