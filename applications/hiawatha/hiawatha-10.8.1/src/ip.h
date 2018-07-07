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

#ifndef _LIBIP_H
#define _LIBIP_H

#include "config.h"
#include <stdbool.h>
#include <sys/types.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <sys/socket.h>

#define IPv4_LEN sizeof(struct in_addr)
#ifdef ENABLE_IPV6
#define IPv6_LEN sizeof(struct in6_addr)
#define MAX_IP_LEN IPv6_LEN
#define MAX_IP_STR_LEN INET6_ADDRSTRLEN
#else
#define MAX_IP_LEN IPv4_LEN
#define MAX_IP_STR_LEN INET_ADDRSTRLEN
#endif

typedef unsigned long t_ipv4;

typedef struct {
	int  family;
	char value[MAX_IP_LEN];
	int  size;
} t_ip_addr;

typedef struct type_iplist {
	t_ip_addr ip;
	int netmask;

	struct type_iplist *next;
} t_iplist;

int  default_ipv4(t_ip_addr *ip_addr);
#ifdef ENABLE_IPV6
int  default_ipv6(t_ip_addr *ip_addr);
#endif
int  set_to_localhost(t_ip_addr *ip_addr);
int  parse_ip(char *str, t_ip_addr *ip_addr);
unsigned char index_by_ip(t_ip_addr *ip);
int  copy_ip(t_ip_addr *dest, t_ip_addr *src);
bool same_ip(t_ip_addr *ip1, t_ip_addr *ip2);
int  apply_netmask(t_ip_addr *ip, int mask);
bool ip_in_subnet(t_ip_addr *ip, t_ip_addr *subnet, int mask);
int  parse_ip_port(char *line, t_ip_addr *ip, int *port);
int  ip_to_str(t_ip_addr *ip, char *str, int max_len);
int  anonymized_ip_to_str(t_ip_addr *ip, char *str, int max_len);
int  hostname_to_ip(char *hostname, t_ip_addr *ip);
int  parse_iplist(char *line, t_iplist **list);
bool in_iplist(t_iplist *list, t_ip_addr *ip);
void remove_iplist(t_iplist *list);
int  connect_to_server(t_ip_addr *ip_addr, int port);

#endif
