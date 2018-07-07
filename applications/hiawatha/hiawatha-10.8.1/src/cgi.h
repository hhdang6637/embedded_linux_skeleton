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

#ifndef _CGI_H
#define _CGI_H

#include <stdbool.h>
#include <time.h>
#include "liblist.h"
#include "ip.h"
#include "session.h"

#define FCGI_VERSION_1           1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

#define FCGI_HEADER_LENGTH       8

typedef enum { cgi_TIMEOUT = -3, cgi_FORCE_QUIT, cgi_ERROR, cgi_OKE, cgi_END_OF_DATA } t_cgi_result;

typedef struct type_cgi_info {
	t_cgi_type type;
	time_t deadline;

	int to_cgi, from_cgi, cgi_error;

	char *input_buffer, *error_buffer;
	int input_buffer_size, error_buffer_size;
	unsigned long input_len, error_len;

	/* Normal CGI
	 */
	bool wrap_cgi;

	/* FastCGI
	 */
	bool read_header;
	char header[FCGI_HEADER_LENGTH];
	size_t fcgi_data_len;
} t_cgi_info;

int fix_crappy_cgi_headers(t_cgi_info *cgi_info);
char *find_cgi_header(char *buffer, int size, char *header);

/* FastCGI server loadbalancer
 */
int init_load_balancer(t_fcgi_server *fcgi_server);
t_connect_to *select_connect_to(t_fcgi_server *fcgi_server, t_ip_addr *client_ip);
t_fcgi_server *fcgi_server_match(t_fcgi_server **fcgi_server, char *extension);
t_fcgi_server *find_fcgi_server(t_fcgi_server *fcgi_server, char *id);
void manage_load_balancer(t_config *config, time_t now);

/* Normal CGI
 */
pid_t fork_cgi_process(t_session *session, t_cgi_info *cgi_info);
t_cgi_result read_from_cgi_process(t_session *session, t_cgi_info *cgi_info);

/* FastCGI server
 */
int connect_to_fcgi_server(t_connect_to *connect_to);
int send_fcgi_request(t_session *session, int sock);
t_cgi_result read_from_fcgi_server(t_session *session, t_cgi_info *cgi_info);

#endif
