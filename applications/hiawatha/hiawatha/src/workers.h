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

#ifndef _WORKERS_H
#define _WORKERS_H

#include "config.h"

int  start_worker(t_session *session);
#ifdef ENABLE_THREAD_POOL
int  init_workers_module(int pool_size);
void manage_thread_pool(int default_thread_pool_size, int thread_kill_rate);
#ifdef ENABLE_TOMAHAWK
int  count_threads_in_pool(void);
int  count_waiting_workers(void);
int  count_threads_marked_quit(void);
#endif
#endif

#endif
