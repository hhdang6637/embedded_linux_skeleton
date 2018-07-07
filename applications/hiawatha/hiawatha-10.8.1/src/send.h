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

#ifndef _SEND_H
#define _SEND_H

#include <stdbool.h>
#include "global.h"
#include "session.h"

#define FCGI_BUFFER_SIZE (64 * KILOBYTE - 1)

typedef struct {
	int           sock;
	unsigned char data[FCGI_BUFFER_SIZE + 8];
	int           size;
	unsigned char type;
} t_fcgi_buffer;

typedef struct {
	int  socket;
#ifdef ENABLE_TLS
	bool use_tls;
	mbedtls_ssl_context *tls_context;
#endif
} t_stream;

void init_send_module(void);
int send_buffer(t_session *session, const char *buffer, int size);
int send_header(t_session *session);
int send_chunk(t_session *session, const char *chunk, int size);
int send_http_code_header(t_session *session);
int send_http_code_body(t_session *session);
int send_fcgi_buffer(t_fcgi_buffer *fcgi_buffer, const char *buffer, long size);
int send_basic_auth(t_session *session);
int send_digest_auth(t_session *session);
int link_streams(t_stream *stream1, t_stream *stream2, int poll_timeout);

#endif
