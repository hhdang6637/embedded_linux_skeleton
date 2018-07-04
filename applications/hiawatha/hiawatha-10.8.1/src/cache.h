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

#ifndef _CACHE_H
#define _CACHE_H

#include "config.h"

#ifdef ENABLE_CACHE

#include "config.h"
#include <stdbool.h>
#include "global.h"
#include "ip.h"

#define TIME_IN_CACHE      MINUTE
#define MAX_CACHE_TIMER      HOUR
#define MIN_CGI_CACHE_TIMER     2
#define MAX_CGI_CACHE_TIMER  HOUR

typedef enum {cot_file, cot_cgi, cot_rproxy} t_cot_type;

typedef struct type_cached_object {
	char          *file;
	char          *header;
	char          *content;
	off_t         header_length;
	off_t         content_length;
	time_t        deadline;
	time_t        last_changed;
	volatile int  in_use;
	t_ip_addr     last_ip;
	t_cot_type    type;
	bool          close_connection;

	struct type_cached_object *prev;
	struct type_cached_object *next;
} t_cached_object;

/* Generic functions
 */
int init_cache_module(void);
void done_with_cached_object(t_cached_object *object, bool remove_object);
void manage_cache(time_t time);
int clear_cache(void);
#ifdef ENABLE_TOMAHAWK
void print_cache_list(FILE *fp);
off_t size_of_cache(void);
#endif

/* File functions
 */
t_cached_object *add_file_to_cache(t_session *session, char *file);
t_cached_object *search_cache_for_file(t_session *session, char *file);

/* CGI functions
 */
int cgi_cache_time(char *buffer, int size);
t_cached_object *add_cgi_output_to_cache(t_session *session, char *output, int size, int time);
t_cached_object *search_cache_for_cgi_output(t_session *session);
void handle_remove_header_for_cgi_cache(t_session *session, char *buffer, int size);

/* Reverse Proxy functions
 */
#ifdef ENABLE_RPROXY
int rproxy_cache_time(t_session *session, char *buffer, int size);
t_cached_object *add_rproxy_output_to_cache(t_session *session, char *output, int size, int time);
t_cached_object *search_cache_for_rproxy_output(t_session *session);
void handle_remove_header_for_rproxy_cache(t_session *session, char *buffer, int size);
#endif

#endif

#endif
