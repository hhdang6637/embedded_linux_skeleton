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

#ifndef _SESSION_H
#define _SESSION_H

#include <time.h>
#ifdef ENABLE_TLS
#include "tls.h"
#endif
#include "ip.h"
#include "liblist.h"
#include "serverconfig.h"

#define MAX_CHILD_ID        30000
#define OUTPUT_BUFFER_SIZE      2 * KILOBYTE

#define ec_NONE                  0
#define ec_SOCKET_READ_ERROR    -1
#define ec_SOCKET_WRITE_ERROR   -2
#define ec_MAX_REQUESTSIZE      -3
#define ec_TIMEOUT              -4
#define ec_CLIENT_DISCONNECTED  -5
#define ec_FORCE_QUIT           -6
#define ec_SQL_INJECTION        -7
#define ec_XSS                  -8
#define ec_CSRF                 -9
#define ec_INVALID_URL          -10

typedef enum { no_cgi, binary, script, fastcgi } t_cgi_type;
typedef enum { unknown, GET, POST, HEAD, TRACE, PUT, DELETE, CONNECT, WHEN, unsupported } t_req_method;
typedef enum { missing_slash, require_tls, location, enforce_first_hostname } t_cause_of_30x;

typedef struct type_session {
	t_config        *config;

	int             error_cause;
	time_t          time;
	int             client_id;
	int             client_socket;
	t_binding       *binding;
	bool            socket_open;
	bool            via_trusted_proxy;
	bool            parsing_oke;
	bool            keep_alive;
	int             kept_alive;
	t_cgi_type      cgi_type;
	char            *cgi_handler;
	t_fcgi_server   *fcgi_server;
	char            *request, *method, *uri, *path_info, *vars, *http_version, *body, *file_on_disk;
	long            header_length, content_length, buffer_size, bytes_in_buffer;
	t_req_method    request_method;
	char            *extension;
	char            *request_uri;
	int             uri_len;
	bool            header_sent;
	bool            data_sent;
	char            *local_user;
	bool            force_quit;
	bool            uri_is_dir;
	bool            encode_gzip;
	t_keyvalue      *alias;
	t_keyvalue      *script_alias;
	bool            request_limit;
	t_http_header   *http_headers;
	t_ip_addr       ip_address;
	char            *mimetype;
	char            *hostname;
	t_host          *host;
	t_host          *last_host;
	bool            host_copied;
	char            *remote_user;
	t_auth_method   http_auth;
	t_directory     *directory;
	bool            handling_error;
	char            *reason_for_403;
	char            *cookies;
	off_t           bytes_sent;
	int             return_code;
	int             error_code;
	bool            log_request;
	t_tempdata      *tempdata;
	char            *uploaded_file;
	char            *location;
	bool            send_date;
	bool            send_expires;
	int             expires;
	bool            caco_private;
	t_cause_of_30x  cause_of_30x;
#ifdef ENABLE_TOOLKIT
	char            *toolkit_fastcgi;
#endif
#ifdef ENABLE_XSLT
	char            *xslt_file;
#endif
	bool            letsencrypt_auth_request;

	/* Throttling: send_buffer() in send.c
	 */
	long            throttle;
	long            bytecounter;
	int             throttle_timer;
	bool            part_of_dirspeed;

	/* Flooding protection
	 */
	time_t          flooding_timer;

	/* TLS
	 */
#ifdef ENABLE_TLS
	mbedtls_ssl_context tls_context;
#endif

	/* Output buffer
	 */
	char            output_buffer[OUTPUT_BUFFER_SIZE];
	int             output_size;

#ifdef ENABLE_DEBUG
	int             thread_id;
	char            *current_task;
#endif

#ifdef ENABLE_RPROXY
	/* Reverse proxy keep-alive
	 */
	bool            rproxy_kept_alive;
	t_ip_addr       rproxy_addr;
	int             rproxy_port;
	int             rproxy_socket;
#ifdef ENABLE_TLS
	bool            rproxy_use_tls;
	mbedtls_ssl_context rproxy_ssl;
#endif
#endif
} t_session;

void init_session(t_session *session);
void reset_session(t_session *session);
void destroy_session(t_session *session);

void determine_request_method(t_session *session);
int  get_target_extension(t_session *session);

int  get_homedir(t_session *session, char *username);
bool duplicate_host(t_session *session);
int  load_user_root_config(t_session *session);
int  load_user_config(t_session *session);
int  copy_directory_settings(t_session *session);
int  remove_port_from_hostname(t_session *session);
int  prevent_xss(t_session *session);
int  init_sqli_detection(void);
int  prevent_sqli(t_session *session);
int  prevent_csrf(t_session *session);
void close_socket(t_session *session);
int  handle_connection_not_allowed(t_session *session, int connections);
bool file_can_be_compressed(t_session *session);
#ifdef ENABLE_DEBUG
void printhex(char *str, int len);
#endif

#endif
