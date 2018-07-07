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

#ifndef _HTTP_H
#define _HTTP_H

#include <stdbool.h>
#include "session.h"

int fetch_request(t_session *session);
int parse_request(t_session *session, int total_bytes);
int uri_to_path(t_session *session);
int get_path_info(t_session *session);
bool validate_url(t_session *session);
const char *http_error(int code);
bool empty_body_because_of_http_status(int status);
int last_forwarded_ip(t_http_header *http_headers, t_ip_addr *ip_addr);

#endif
