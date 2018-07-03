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

#ifndef _HTTPAUTH_H
#define _HTTPAUTH_H

#include "session.h"

int  init_httpauth_module(void);
bool group_oke(t_session *session, char *user, t_charlist *group);
int  http_authentication_result(t_session *session, bool access_on_pwdfile_missing);

#endif
