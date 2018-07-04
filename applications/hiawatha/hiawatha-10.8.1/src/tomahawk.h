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

#ifndef _TOMAHAWK_H
#define _TOMAHAWK_H

#include "config.h"

#ifdef ENABLE_TOMAHAWK

#include <poll.h>
#include "serverconfig.h"
#include "ip.h"
#include "liblist.h"

#define cc_OKE            0
#define cc_DISCONNECT     1

#define COUNTER_CLIENT    0
#define COUNTER_FILE      1
#define COUNTER_CGI       2
#define COUNTER_INDEX     3
#define COUNTER_BAN       4
#define COUNTER_DENY      5
#define COUNTER_EXPLOIT   6
#define COUNTER_MAX       7

#define TRANSFER_SEND     0
#define TRANSFER_RECEIVED 1
#define TRANSFER_MAX      2

typedef struct type_admin {
	int socket;
	struct pollfd *poll_data;
	FILE *fp;
	bool authenticated;
	int timer;
	bool show_requests;

	struct type_admin *next;
} t_admin;

void increment_counter(int counter);
void increment_transfer(int counter, long bytes);
void show_request_to_admins(char *method, char *uri, char *http_version, t_ip_addr *ip_addr,
                            t_http_header *header, int response_code, off_t bytes_sent);

int  init_tomahawk_module(void);
int  add_admin(int sock);
void disconnect_admins(void);
void check_admin_list(void);
int prepare_admins_for_poll(struct pollfd *current_poll);
void handle_admins(t_config *config);

#endif

#endif
