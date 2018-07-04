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

#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include "libstr.h"
#include "ip.h"
#include "memdbg.h"

char *unknown_ip = "<unknown>";

int default_ipv4(t_ip_addr *ip_addr) {
	/* set to 0.0.0.0
	 */
	if (ip_addr == NULL) {
		return -1;
	}

	memset(ip_addr->value, 0, IPv4_LEN);
	ip_addr->family = AF_INET;
	ip_addr->size = IPv4_LEN;

	return 0;
}

#ifdef ENABLE_IPV6
int default_ipv6(t_ip_addr *ip_addr) {
	/* set to ::
	 */
	if (ip_addr == NULL) {
		return -1;
	}

	memset(ip_addr->value, 0, IPv6_LEN);
	ip_addr->family = AF_INET6;
	ip_addr->size = IPv6_LEN;

	return 0;
}
#endif

int set_to_localhost(t_ip_addr *ip_addr) {
	t_ipv4 *ipv4;

	/* Set to 127.0.0.1
	 */
	if (ip_addr == NULL) {
		return -1;
	}

	ipv4 = (t_ipv4*)&(ip_addr->value);
	*ipv4 = htonl(0x7F000001);
	ip_addr->family = AF_INET;
	ip_addr->size = IPv4_LEN;

	return 0;
}

int parse_ip(char *str, t_ip_addr *ip_addr) {
	if ((str == NULL) || (ip_addr == NULL)) {
		return -1;
	}

	if (inet_pton(AF_INET, str, ip_addr->value) > 0) {
		ip_addr->family = AF_INET;
		ip_addr->size = IPv4_LEN;
#ifdef ENABLE_IPV6
	} else if (inet_pton(AF_INET6, str, ip_addr->value) > 0) {
		ip_addr->family = AF_INET6;
		ip_addr->size = IPv6_LEN;
#endif
	} else {
		ip_addr->family = AF_UNSPEC;
		ip_addr->size = 0;

		return -1;
	}

	return ip_addr->family;
}

unsigned char index_by_ip(t_ip_addr *ip) {
	unsigned char index = 0;
	int i;

	if (ip != NULL) {
		for (i = 0; i < ip->size; i++) {
			index += ip->value[i];
		}
	}

	return index;
}

int copy_ip(t_ip_addr *dest, t_ip_addr *src) {
	if ((dest == NULL) || (src == NULL)) {
		return -1;
	} else if ((unsigned int)src->size > MAX_IP_LEN) {
		return -1;
	}

	dest->family = src->family;
	memcpy(dest->value, src->value, src->size);
	dest->size = src->size;

	return 0;
}

bool same_ip(t_ip_addr *ip1, t_ip_addr *ip2) {
	if ((ip1 != NULL) && (ip2 != NULL)) {
		if ((ip1->family == ip2->family) && (ip1->size == ip2->size)) {
			return (memcmp(ip1->value, ip2->value, ip1->size) == 0);
		}
	}

	return false;
}

int apply_netmask(t_ip_addr *ip, int mask) {
	int byte;

	if (ip == NULL) {
		return -1;
	} else if (ip->family == AF_INET) {
		byte = IPv4_LEN - 1;
		mask = (8 * IPv4_LEN) - mask;
#ifdef ENABLE_IPV6
	} else if (ip->family == AF_INET6) {
		byte = IPv6_LEN - 1;
		mask = (8 * IPv6_LEN) - mask;
#endif
	} else {
		return -1;
	}

	while ((byte >= 0) && (mask > 0)) {
		if (mask >= 8) {
			ip->value[byte] = 0;
		} else {
			ip->value[byte] = (ip->value[byte] >> mask) << mask;
		}

		byte--;
		mask -= 8;
	}

	return 0;
}

bool ip_in_subnet(t_ip_addr *ip, t_ip_addr *subnet, int mask) {
	t_ip_addr test_ip;

	if ((ip == NULL) || (subnet == NULL)) {
		return false;
	} else if (ip->family != subnet->family) {
		return false;
	}

	/* Apply mask to client IP
	 */
	copy_ip(&test_ip, ip);
	if (apply_netmask(&test_ip, mask) == -1) {
		return false;
	}

	return same_ip(&test_ip, subnet);
}

int parse_ip_port(char *line, t_ip_addr *ip, int *port) {
	char *s_ip, *s_port, sep = '?';

	if ((line == NULL) || (ip == NULL) || (port == NULL)) {
		return -1;
	}

#ifdef ENABLE_IPV6
	if (split_string(line, &s_ip, &s_port, ']') == 0) {
		if ((*s_ip != '[') || (*s_port != ':')) {
			return -1;
		}
		s_ip = remove_spaces(s_ip + 1);
		s_port = remove_spaces(s_port + 1);
	} else
#endif
	{
		s_port = line + strlen(line);
		do {
			if (s_port <= line) {
				return -1;
			}
			s_port--;
		} while ((*s_port != ':') && (*s_port != '.'));
		sep = *s_port;
		*s_port = '\0';
		s_ip = remove_spaces(line);
		s_port = remove_spaces(s_port + 1);
	}

	if (parse_ip(s_ip, ip) == -1) {
		return -1;
	} else if ((*port = str_to_int(s_port)) <= 0) {
		return -1;
	}

	if (sep != '?') {
		if ((ip->family == AF_INET) && (sep != ':')) {
			return -1;
		}
#ifdef ENABLE_IPV6
		if ((ip->family == AF_INET6) && (sep != '.')) {
			return -1;
		}
#endif
	}

	return 0;
}

/* Write an IP address to a logfile.
 */
int ip_to_str(t_ip_addr *ip, char *str, int max_len) {
	if (inet_ntop(ip->family, &(ip->value), str, max_len) == NULL) {
		strncpy(str, unknown_ip, max_len);
		str[max_len - 1] = '\0';
		return -1;
	}

	return 0;
}

/* Anonymize an IP address and write it to a logfile.
 */
int anonymized_ip_to_str(t_ip_addr *ip, char *str, int max_len) {
	t_ip_addr anonymized_ip;
	int mask;

	if (ip == NULL) {
		strncpy(str, unknown_ip, max_len);
		str[max_len - 1] = '\0';
		return -1;
	} else if (ip->family == AF_INET) {
		mask = 24;
#ifdef ENABLE_IPV6
	} else if (ip->family == AF_INET6) {
		mask = 32;
#endif
	} else {
		strncpy(str, unknown_ip, max_len);
		str[max_len - 1] = '\0';
		return -1;
	}

	copy_ip(&anonymized_ip, ip);
	if (apply_netmask(&anonymized_ip, mask) == -1) {
		strncpy(str, unknown_ip, max_len);
		str[max_len - 1] = '\0';
		return -1;
	}

	return ip_to_str(&anonymized_ip, str, max_len);
}

/* Convert hostname to an IP address
 */
int hostname_to_ip(char *hostname, t_ip_addr *ip) {
	struct addrinfo *addrinfo;

	if (getaddrinfo(hostname, NULL, NULL, &addrinfo) != 0) {
		return -1;
	}

	while ((addrinfo->ai_next != NULL) && (addrinfo->ai_family != AF_INET)) {
		addrinfo = addrinfo->ai_next;
	}

	if (addrinfo->ai_family == AF_INET) {
		ip->size = IPv4_LEN;
		memcpy(&ip->value, &((struct sockaddr_in*)(addrinfo->ai_addr))->sin_addr, ip->size);
#ifdef ENABLE_IPV6
	} else if (addrinfo->ai_family == AF_INET6) {
		ip->size = IPv6_LEN;
		memcpy(&ip->value, &((struct sockaddr_in6*)(addrinfo->ai_addr))->sin6_addr, ip->size);
#endif
	} else {
		freeaddrinfo(addrinfo);
		return -1;
	}

	ip->family = addrinfo->ai_family;
	freeaddrinfo(addrinfo);

	return 0;
}

int parse_iplist(char *line, t_iplist **list) {
	char *proxy, *mask;
	t_iplist *new;
	bool error = false;

	while (line != NULL) {
		split_string(line, &proxy, &line, ',');

		split_string(proxy, &proxy, &mask, '/');

		if ((new = (t_iplist*)malloc(sizeof(t_iplist))) == NULL) {
			error = true;
			break;
		}

		new->next = *list;
		*list = new;

		if (parse_ip(proxy, &(new->ip)) == -1) {
			error = true;
			break;
		}

		if (mask != NULL) {
			if ((new->netmask = str_to_int(mask)) == -1) {
				error = true;
				break;
			}
		} else if (new->ip.family == AF_INET) {
			new->netmask = 8 * IPv4_LEN;
#ifdef ENABLE_IPV6
		} else if (new->ip.family == AF_INET6) {
			new->netmask = 8 * IPv6_LEN;
#endif
		} else {
			error = true;
			break;
		}
	}

	if (error) {
		remove_iplist(*list);
		*list = NULL;
		return -1;
	}

	return 0;
}

bool in_iplist(t_iplist *list, t_ip_addr *ip) {
	while (list != NULL) {
		if (ip_in_subnet(ip, &(list->ip), list->netmask)) {
			return true;
		}
		list = list->next;
	}

	return false;
}

void remove_iplist(t_iplist *list) {
	t_iplist *item;

	while (list != NULL) {
		item = list;
		list = list->next;

		free(item);
	}
}

/* Connect to the webserver
 */
int connect_to_server(t_ip_addr *ip_addr, int port) {
	int sock = -1;
	struct sockaddr_in saddr4;
#ifdef ENABLE_IPV6
	struct sockaddr_in6 saddr6;
#endif

	if (ip_addr == NULL) {
		return -1;
	}

	if (ip_addr->family == AF_INET) {
		/* IPv4
		 */
		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) > 0) {
			memset(&saddr4, 0, sizeof(struct sockaddr_in));
			saddr4.sin_family = AF_INET;
			saddr4.sin_port = htons(port);
			memcpy(&saddr4.sin_addr.s_addr, &(ip_addr->value), ip_addr->size);
			if (connect(sock, (struct sockaddr*)&saddr4, sizeof(struct sockaddr_in)) != 0) {
				close(sock);
				sock = -1;
			}
		}
#ifdef ENABLE_IPV6
	} else if (ip_addr->family == AF_INET6) {
		/* IPv6
		 */
		if ((sock = socket(AF_INET6, SOCK_STREAM, 0)) > 0) {
			memset(&saddr6, 0, sizeof(struct sockaddr_in6));
			saddr6.sin6_family = AF_INET6;
			saddr6.sin6_port = htons(port);
			memcpy(&saddr6.sin6_addr.s6_addr, &(ip_addr->value), ip_addr->size);
			if (connect(sock, (struct sockaddr*)&saddr6, sizeof(struct sockaddr_in6)) != 0) {
				close(sock);
				sock = -1;
			}
		}
#endif
	}

	return sock;
}
