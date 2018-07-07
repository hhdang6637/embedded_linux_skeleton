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

#ifndef _TARGET_H
#define _TARGET_H

#include "session.h"
#ifdef ENABLE_RPROXY
#include "rproxy.h"
#endif

int send_file(t_session *session);
int execute_cgi(t_session *session);
int handle_trace_request(t_session *session);
int handle_put_request(t_session *session);
int handle_delete_request(t_session *session);
#ifdef ENABLE_XSLT
int handle_xml_file(t_session *session, char *xslt_file);
#endif
#ifdef ENABLE_RPROXY
int proxy_request(t_session *session, t_rproxy *proxy);
#endif
int forward_to_websocket(t_session *session);

#endif
