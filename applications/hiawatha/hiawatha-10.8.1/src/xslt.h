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

#ifndef _XSLT_H
#define _XSLT_H

#include "config.h"

#if defined(ENABLE_XSLT) || defined(ENABLE_MONITOR)

#include <stdbool.h>
#include "session.h"

#ifdef ENABLE_XSLT
void init_xslt_module();
char *find_xslt_file(t_session *session);
int transform_xml(t_session *session, char *xslt_file);
#endif
int show_index(t_session *session);
#ifdef ENABLE_XSLT
int show_http_code_body(t_session *session);
#endif

#endif

#endif
