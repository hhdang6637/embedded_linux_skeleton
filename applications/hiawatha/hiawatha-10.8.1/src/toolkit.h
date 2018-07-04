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

#ifndef _TOOLKIT_H
#define _TOOLKIT_H

#include "config.h"

#ifdef ENABLE_TOOLKIT

#include <stdbool.h>
#include <regex.h>
#include "liblist.h"

#define UT_ERROR        -1
#define UT_RETURN        0
#define UT_EXIT          1
#define UT_REDIRECT    301
#define UT_DENY_ACCESS 403
#define UT_NOT_FOUND   404

#define IU_NOTFOUND      0
#define IU_EXISTS        1
#define IU_ISFILE        2
#define IU_ISDIR         3

typedef enum { tc_none, tc_header, tc_match, tc_method, tc_request_uri, tc_total_connections
#ifdef ENABLE_TLS
               , tc_use_tls
#endif
               } t_toolkit_condition;
typedef enum { to_none, to_ban, to_deny_access, to_fastcgi, to_not_found, to_omit_request_log,
               to_redirect, to_rewrite, to_skip, to_sub, to_use } t_toolkit_operation;
typedef enum { tf_continue, tf_exit, tf_return } t_toolkit_flow;

typedef struct type_toolkit_rule {
	t_toolkit_condition condition;
	t_toolkit_operation operation;
	t_toolkit_flow flow;

	regex_t pattern;
	int match_loop;
	char *parameter;
	bool neg_match;
	char *header;
	int value;
	bool caco_private;
	bool case_insensitive;

	struct type_toolkit_rule *next;
} t_toolkit_rule;

typedef struct type_url_toolkit {
	char *toolkit_id;
	struct type_toolkit_rule *toolkit_rule;

	struct type_url_toolkit *next;
} t_url_toolkit;

typedef struct type_toolkit_options {
	int  sub_depth;
	char *new_url;
	char *method;
	char *website_root;
	char *fastcgi_server;
	int  status_code;
	int  ban;
	bool caco_private;
	int  total_connections;
	bool log_request;
#ifdef ENABLE_TLS
	bool use_tls;
#endif
	bool allow_dot_files;
	t_url_toolkit *url_toolkit;
	t_http_header *http_headers;
} t_toolkit_options;

t_url_toolkit *select_toolkit(char *toolkit_id, t_url_toolkit *url_toolkit);
bool toolkit_setting(char *key, char *value, t_url_toolkit *toolkit);
t_url_toolkit *new_url_toolkit(void);
bool toolkit_rules_oke(t_url_toolkit *url_toolkit);
void init_toolkit_options(t_toolkit_options *options);
int use_toolkit(char *url, t_url_toolkit *toolkit, t_toolkit_options *options);

#endif

#endif
