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

#ifndef _MONITOR_H
#define _MONITOR_H

#include "config.h"

#ifdef ENABLE_MONITOR

#include <time.h>
#include "serverconfig.h"
#include "session.h"

int  init_monitor_module(t_config *config);
void shutdown_monitor_module(void);

int  monitor_event(char *event, ...);
int  monitor_version(char *version, char *modules);
int  monitor_stats_to_buffer(t_config *config, time_t now);

void monitor_count_connection(t_session *session);
void monitor_count_bad_request(t_session *session);

void monitor_count_host(t_session *session);
void monitor_count_ban(t_session *session);
void monitor_count_exploit_attempt(t_session *session);
void monitor_count_failed_login(t_session *session);
void monitor_count_cgi(t_session *session, int time, bool timed_out, bool error);

#endif

#endif
