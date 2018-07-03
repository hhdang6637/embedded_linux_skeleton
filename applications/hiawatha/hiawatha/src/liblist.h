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

#ifndef _LIBLIST_H
#define _LIBLIST_H

#include <stdbool.h>
#include "global.h"
#include "ip.h"

typedef enum { deny, allow, pwd, unspecified } t_access;
typedef enum { tc_data, tc_charlist, tc_accesslist, tc_keyvalue, tc_errorhandler } t_tempdata_type;

typedef struct type_http_header {
	char *data;
	int  length;
	int  value_offset;

	struct type_http_header *next;
} t_http_header;

typedef struct type_charlist {
	int  size;
	char **item;
} t_charlist;

typedef struct type_accesslist {
	t_ip_addr ip;
	int netmask;
	bool all_ip;
	t_access access;

	struct type_accesslist *next;
} t_accesslist;

typedef struct type_keyvalue {
	char *key;
	char *value;
	size_t key_len, value_len;

	struct type_keyvalue *next;
} t_keyvalue;

typedef struct type_tempdata {
	void *content;
	t_tempdata_type type;

	struct type_tempdata *next;
} t_tempdata;

typedef struct type_ipcounterlist {
	t_ip_addr ip;
	int count;

	struct type_ipcounterlist *next;
} t_ipcounterlist;

typedef struct type_error_handler {
	int  code;
	char *handler;
	char *parameters;

	struct type_error_handler *next;
} t_error_handler;

t_http_header *parse_http_headers(char *line);
char *get_http_header(char *key, t_http_header *http_headers);
char *get_referer_header(t_http_header *http_headers);
t_http_header *remove_http_headers(t_http_header *http_headers);

void init_charlist(t_charlist *list);
int  parse_charlist(char *value, t_charlist *list);
void copy_charlist(t_charlist *dest, t_charlist *src);
bool in_charlist(char *item, t_charlist *list);
bool matches_charlist(char *item, t_charlist *list);
void remove_charlist(t_charlist *list);

t_accesslist *parse_accesslist(char *line, bool pwd_allowed, t_accesslist *list);
t_accesslist *remove_accesslist(t_accesslist *list);
t_access ip_allowed(t_ip_addr *ip, t_accesslist *list);

int  parse_keyvalue(char *line, t_keyvalue **kvlist, char *delimiter);
t_keyvalue *remove_keyvaluelist(t_keyvalue *list);

int  parse_error_handler(char *line, t_error_handler **handlers);
void remove_error_handler(t_error_handler *handler);

int  register_tempdata(t_tempdata **tempdata, void *data, t_tempdata_type type);
void remove_tempdata(t_tempdata *tempdata);

#endif
