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

#ifndef _LOG_H
#define _LOG_H

#include "global.h"
#include "ip.h"
#include "session.h"

#define LOG_PERM (S_IRUSR|S_IWUSR|S_IRGRP)
#define log_error_session(session, ...) log_error_file(session, NULL, __VA_ARGS__)

int  init_log_module(void);
void log_pid(t_config *config, pid_t pid, uid_t server_uid);
void log_system(t_config *config, char *mesg, ...);
void log_system_session(t_session *session, char *mesg, ...);
void log_error_file(t_session *session, char *file, char *mesg, ...);
void log_error_cgi(t_session *session, char *mesg);
void log_request(t_session *session);
void log_garbage(t_session *session);
void log_exploit_attempt(t_session *session, char *type, char *data);
void log_unban(t_config *config, t_ip_addr *ip_address, unsigned long connect_attempts);
void close_logfiles(t_host *host, time_t now);
void close_logfiles_for_cgi_run(t_host *host);
void rotate_access_logfiles(t_config *config, time_t now);
#ifdef ENABLE_DEBUG
void log_debug(t_session *session, char *mesg, ...);
#endif

#endif
