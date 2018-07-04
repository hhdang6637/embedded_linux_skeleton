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

#ifndef _CLIENT_H
#define _CLIENT_H

#include <stdbool.h>
#include <time.h>
#include "global.h"
#include "ip.h"
#include "serverconfig.h"
#include "session.h"

#define ca_TOOMUCH_PERIP  -1
#define ca_TOOMUCH_TOTAL  -2
#define ca_BANNED         -3

int  init_client_module(void);
int  add_client(t_session *session);
int  reposition_client(t_session *session, t_ip_addr *ip_address);
int  mark_client_for_removal(t_session *session, int delay);
void check_remove_deadlines(t_config *config, time_t now);
int  remove_client(t_session *session, bool free_session);
int  connection_allowed(t_ip_addr *ip, bool ip_of_proxy, int max_per_ip, int max_total);
int  count_registered_connections(void);
int  disconnect_clients(t_config *config);
bool client_is_flooding(t_session *session);
void check_flooding(t_config *config);

int  kick_client(int id);
int  kick_ip(t_ip_addr *ip);

int  ban_ip(t_ip_addr *ip, int timer, bool kick_on_ban);
void reban_ip(t_ip_addr *ip);
void check_ban_list(t_config *config, time_t now);
int  unban_ip(t_ip_addr *ip);

int  register_wrong_password(t_session *session);
void remove_wrong_password_list(t_config *config);

void close_client_sockets_for_cgi_run(void);

#ifdef ENABLE_TOMAHAWK
void print_client_list(FILE *fp);
void print_ban_list(FILE *fp);
int  number_of_bans(void);
#endif

#endif
