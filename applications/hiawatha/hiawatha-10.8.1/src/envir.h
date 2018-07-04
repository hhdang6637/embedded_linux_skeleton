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

#ifndef _ENVIR_H
#define _ENVIR_H

#include "session.h"
#include "send.h"

int http_header_to_environment(t_session *session, t_fcgi_buffer *fcgi_buffer, char *key, char *envir);
void set_environment(t_session *session, t_fcgi_buffer *fcgi_buffer);

#endif
