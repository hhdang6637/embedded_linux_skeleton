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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "global.h"
#include "libstr.h"
#include "liblist.h"
#include "memdbg.h"

/*---< headerlist >-----------------------------------------------------------*/

/* Parse the HTTP http_headers from the received request.
 */
t_http_header *parse_http_headers(char *line) {
	t_http_header *first, *http_header;
	char *value;

	if (empty_string(line)) {
		return NULL;
	} else if (*line == '\0') {
		return NULL;
	}

	if ((first = http_header = (t_http_header*)malloc(sizeof(t_http_header))) == NULL) {
		return NULL;
	}
	http_header->data = line;
	http_header->length = 0;
	http_header->next = NULL;
	while (*line != '\0') {
		if (*line == '\r') {
			*line = '\0';
			http_header->length = strlen(http_header->data);
			if (*(line + 1) == '\n') {
				if ((*(line + 2) != '\r') && (*(line + 2) != '\0')) {
					if ((http_header->next = (t_http_header*)malloc(sizeof(t_http_header))) == NULL) {
						return first;
					}
					http_header = http_header->next;
					http_header->next = NULL;
					http_header->data = line + 2;
					http_header->length = 0;
				} else {
					break;
				}
			} else {
				http_header->data = line + 1;
			}
		}
		line++;
	}

	if (first->length == 0) {
		free(first);
		return NULL;
	}

	if (http_header->length == 0) {
		http_header->length = strlen(http_header->data);
	}

	http_header = first;
	while (http_header != NULL) {
		if ((value = strchr(http_header->data, ':')) != NULL) {
			do {
				value++;
			} while (*value == ' ');
			http_header->value_offset = (value - http_header->data);
		} else {
			http_header->value_offset = 0;
		}
		http_header = http_header->next;
	}

	return first;
}

/* Search for a http_header and return its value.
 */
char *get_http_header(char *key, t_http_header *http_headers) {
	int len;

	if ((key == NULL) || (http_headers == NULL)) {
		return NULL;
	}

	len = strlen(key);
	while (http_headers != NULL) {
		if (strncasecmp(http_headers->data, key, len) == 0) {
			return http_headers->data + http_headers->value_offset;
		}
		http_headers = http_headers->next;
	}

	return NULL;
}

/* Return the HTTP Origin or Referer header
 */
char *get_referer_header(t_http_header *http_headers) {
	char *referer;

	if ((referer = get_http_header("Origin:", http_headers)) == NULL) {
		referer = get_http_header("Referer:", http_headers);
	}

	return referer;
}

/* free() a list of http_headers.
 */
t_http_header *remove_http_headers(t_http_header *http_headers) {
	t_http_header *remove;

	while (http_headers != NULL) {
		remove = http_headers;
		http_headers = http_headers->next;

		free(remove);
	}

	return NULL;
}

/*---< charlist >-------------------------------------------------------------*/

void init_charlist(t_charlist *list) {
	if (list != NULL) {
		list->size = 0;
		list->item = NULL;
	}
}

int parse_charlist(char *value, t_charlist *list) {
	char *scan, **new;
	int add = 1, i;

	if (list == NULL) {
		return -1;
	} else if (empty_string(value)) {
		return -1;
	}

	scan = value;
	while (*scan != '\0') {
		if (*scan == ',') {
			*scan = '\0';
			add++;
		}
		scan++;
	}

	if ((new = (char**)realloc(list->item, (list->size + add) * sizeof(char*))) == NULL) {
		return -1;
	}
	list->item = new;

	for (i = 0; i < add; i++) {
		*(list->item + list->size + i) = NULL;
	}

	for (i = 0; i < add; i++) {
		if ((*(list->item + list->size + i) = strdup(remove_spaces(value))) == NULL) {
			remove_charlist(list);
			init_charlist(list);
			return -1;
		}
		value = value + strlen(value) + 1;
	}

	list->size += add;

	return 0;
}

void copy_charlist(t_charlist *dest, t_charlist *src) {
	if ((dest != NULL) && (src != NULL)) {
		dest->size = src->size;
		dest->item = src->item;
	}
}

bool in_charlist(char *item, t_charlist *list) {
	int i;

	if ((item == NULL) || (list == NULL)) {
		return false;
	}

	i = list->size;
	while (i-- > 0) {
		if (strcmp(*(list->item + i), item) == 0) {
			return true;
		}
	}

	return false;
}

bool matches_charlist(char *item, t_charlist *list) {
	int i;
	size_t n;

	if ((item == NULL) || (list == NULL)) {
		return false;
	}

	n = strlen(item);

	i = list->size;
	while (i-- > 0) {
		if (strncmp(*(list->item + i), item, n) == 0) {
			return true;
		}
	}

	return false;
}

void remove_charlist(t_charlist *list) {
	if (list != NULL) {
		if (list->size > 0) {
			do {
				list->size--;
				check_free(*(list->item + list->size));
			} while (list->size > 0);
			check_free(list->item);
			list->item = NULL;
		}
	}
}

/*---< accesslist >-----------------------------------------------------------*/

/* Parse a list of access levels.
 */
t_accesslist *parse_accesslist(char *line, bool pwd_allowed, t_accesslist *list) {
	t_accesslist *new = NULL;
	char *rule, *ip, *mask;
	bool error = false;

	if (empty_string(line)) {
		return remove_accesslist(list);
	}

	if (list != NULL) {
		new = list;
		while (new->next != NULL) {
			new = new->next;
		}
	}

	while (line != NULL) {
		split_string(line, &ip, &line, ',');
		if (split_string(ip, &rule, &ip, ' ') == 0) {
			if (list == NULL) {
				if ((list = new = (t_accesslist*)malloc(sizeof(t_accesslist))) == NULL) {
					break;
				}
			} else {
				if ((new->next = (t_accesslist*)malloc(sizeof(t_accesslist))) == NULL)  {
					error = true;
					break;
				}
				new = new->next;
			}
			new->next = NULL;

			if (strcasecmp(rule, "allow") == 0) {
				new->access = allow;
			} else if (strcasecmp(rule, "deny") == 0) {
				new->access = deny;
			} else if (pwd_allowed && (strcasecmp(rule, "pwd") == 0)) {
				new->access = pwd;
			} else {
				error = true;
				break;
			}
			if (strcasecmp(ip, "all") == 0) {
				default_ipv4(&(new->ip));
				new->netmask = 0;
				new->all_ip = true;
			} else {
				new->all_ip = false;
				if (split_string(ip, &ip, &mask, '/') == 0) {
					if ((new->netmask = str_to_int(mask)) == -1) {
						error = true;
						break;
					}
				} else {
					new->netmask = -1;
				}
				if (parse_ip(ip, &(new->ip)) == -1) {
					error = true;
					break;
				}

				if (new->netmask == -1) {
					/* Set netmask
					 */
					if (new->ip.family == AF_INET) {
						new->netmask = 8 * IPv4_LEN;
#ifdef ENABLE_IPV6
					} else if (new->ip.family == AF_INET6) {
						new->netmask = 8 * IPv6_LEN;
#endif
					} else {
						error = true;
						break;
					}
				} else {
					/* Check netmask
					 */
					if (new->ip.family == AF_INET) {
						if ((unsigned int)new->netmask > 8 * IPv4_LEN) {
							error = true;
							break;
						}
#ifdef ENABLE_IPV6
					} else if (new->ip.family == AF_INET6) {
						if ((unsigned int)new->netmask > 8 * IPv6_LEN) {
							error = true;
							break;
						}
#endif
					} else {
						error = true;
						break;
					}
				}

				/* Apply subnetmask
				 */
				if (apply_netmask(&(new->ip), new->netmask) == -1) {
					error = true;
					break;
				}
			}
		} else {
			error = true;
			break;
		}
	}

	if (error) {
		list = remove_accesslist(list);
	}

	return list;
}

/* Remove an accesslist.
 */
t_accesslist *remove_accesslist(t_accesslist *list) {
	t_accesslist *item;

	while (list != NULL) {
		item = list;
		list = list->next;

		free(item);
	}

	return NULL;
}

/* Return the access status of an IP address.
 */
t_access ip_allowed(t_ip_addr *ip, t_accesslist *list) {
	while (list != NULL) {
		if (list->all_ip) {
			return list->access;
		} else if (ip_in_subnet(ip, &(list->ip), list->netmask)) {
			return list->access;
		}
		list = list->next;
	}

	return unspecified;
}

/*---< key/value >-----------------------------------------------------------*/

/* Parse a key/value combination.
 */
int parse_keyvalue(char *line, t_keyvalue **kvlist, char *delimiter) {
	char *value;
	t_keyvalue *prev;

	if ((kvlist == NULL) || (delimiter == NULL)) {
		return -1;
	} else if (empty_string(line)) {
		return -1;
	}

	if ((value = strstr(line, delimiter)) == NULL) {
		return -1;
	}

	*value = '\0';
	value += strlen(delimiter);

	prev = *kvlist;
	if ((*kvlist = (t_keyvalue*)malloc(sizeof(t_keyvalue))) == NULL) {
		return -1;
	}
	(*kvlist)->next = prev;

	(*kvlist)->value = NULL;
	if (((*kvlist)->key = strdup(remove_spaces(line))) == NULL) {
		free(*kvlist);
		return -1;
	}
	(*kvlist)->key_len = strlen((*kvlist)->key);

	if (((*kvlist)->value = strdup(remove_spaces(value))) == NULL) {
		free((*kvlist)->key);
		free(*kvlist);
		return -1;
	}
	(*kvlist)->value_len = strlen((*kvlist)->value);

	return 0;
}

t_keyvalue *remove_keyvaluelist(t_keyvalue *list) {
	t_keyvalue *remove;

	while (list != NULL) {
		remove = list;
		list = list->next;

		check_free(remove->key);
		check_free(remove->value);
		free(remove);
	}

	return NULL;
}

/*---< error handlers >------------------------------------------------------*/

int parse_error_handler(char *line, t_error_handler **handlers) {
	t_error_handler *handler;
	char *param;
	int code;

	if (empty_string(line)) {
		return -1;
	} else if ((handler = (t_error_handler*)malloc(sizeof(t_error_handler))) == NULL) {
		return -1;
	}

	if (split_string(line, &param, &line, ':') != 0) {
		free(handler);
		return -1;
	}

	switch (code = str_to_int(param)) {
		case 401:
		case 403:
		case 404:
		case 501:
		case 503:
			handler->code = code;
			break;
		default:
			free(handler);
			return -1;
	}

	if ((strlen(line) > 128) || (*line != '/')) {
		free(handler);
		return -1;
	} else if ((handler->handler = strdup(line)) == NULL) {
		free(handler);
		return -1;
	}

	if ((param = strchr(handler->handler, '?')) != NULL) {
		*param = '\0';
		handler->parameters = param + 1;
	} else {
		handler->parameters = NULL;
	}

	handler->next = *handlers;
	*handlers = handler;

	return 0;
}

void remove_error_handler(t_error_handler *handler) {
	if (handler != NULL) {
		free(handler->handler);
		free(handler);
	}
}

/*---< temporary data >------------------------------------------------------*/

int register_tempdata(t_tempdata **tempdata, void *data, t_tempdata_type type) {
	t_tempdata *tdata;

	if (tempdata == NULL) {
		return 0;
	} else if (data == NULL) {
		return -1;
	} else if ((tdata = (t_tempdata*)malloc(sizeof(t_tempdata))) == NULL) {
		return -1;
	}

	tdata->content = data;
	tdata->type = type;
	tdata->next = *tempdata;
	*tempdata = tdata;

	return 0;
}

void remove_tempdata(t_tempdata *tempdata) {
	t_tempdata *tdata;

	while (tempdata != NULL) {
		tdata = tempdata;
		tempdata = tempdata->next;

		switch (tdata->type) {
			case tc_data:
				check_free(tdata->content);
				break;
			case tc_accesslist:
				remove_accesslist((t_accesslist*)tdata->content);
				break;
			case tc_keyvalue:
				free(((t_keyvalue*)(tdata->content))->key);
				free(((t_keyvalue*)(tdata->content))->value);
				free(tdata->content);
				break;
			case tc_charlist:
				remove_charlist((t_charlist*)tdata->content);
				break;
			case tc_errorhandler:
				remove_error_handler((t_error_handler*)tdata->content);
				break;
		}

		free(tdata);
	}
}
