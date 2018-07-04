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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <sys/socket.h>
#include "global.h"
#include "alternative.h"
#include "client.h"
#include "libstr.h"
#include "liblist.h"
#include "session.h"
#include "log.h"
#include "monitor.h"
#include "tomahawk.h"
#include "memdbg.h"

static const struct {
	const char *text;
} sqli_detection[] = {
	{"'\\s*(;\\s*)?--(\\s|')"},
	{"\\s+(and|or|xor|&&|\\|\\|)\\s*\\(?\\s*('|[0-9]|`?[a-z\\._-]+`?\\s*(=|like)|[a-z]+\\s*\\()"},
	{"\\s+(not\\s+)?in\\s*\\(\\s*['0-9]"},
	{"union(\\s+all)?(\\s*\\(\\s*|\\s+)select(`|\\s)"},
	{"select(\\s*`|\\s+)(\\*|[a-z0-9_\\, ]*)(`\\s*|\\s+)from(\\s*`|\\s+)[a-z0-9_\\.]*"},
	{"insert\\s+into(\\s*`|\\s+).*(`\\s*|\\s+)(values\\s*)?\\(.*\\)"},
	{"update(\\s*`|\\s+)[a-z0-9_\\.]*(`\\s*|\\s+)set(\\s*`|\\s+).*="},
	{"delete\\s+from(\\s*`|\\s+)[a-z0-9_\\.]*`?"},
	{"extractvalue\\s*\\(\\s*[0-9'\"@]"},
	{NULL}
};

static const struct {
	const char *text;
} sql_operators[] = {
	{"="}, {":="}, {"&"}, {"~"}, {"|"}, {"^"}, {"/"}, {"<"}, {"="}, {">"},
	{"-"}, {"%"}, {"!"}, {"+"}, {"*"}, {"and"}, {"between"}, {"binary"},
	{"case"}, {"div"}, {"in"}, {"is"}, {"like"}, {"mod"}, {"not"}, {"or"},
	{"order"}, {"regexp"}, {"rlike"}, {"sounds"}, {"xor"},
	{NULL}
};

typedef struct type_sqli_pattern {
	regex_t regex;
	struct type_sqli_pattern *next;
} t_sqli_pattern;

t_sqli_pattern *sqli_patterns = NULL;
static int new_client_id = 0;

/* Set the entries in a session-record to the default values.
 */
static void clear_session(t_session *session) {
	session->time = time(NULL);
	session->cgi_type = no_cgi;
	session->cgi_handler = NULL;
	session->fcgi_server = NULL;
	session->method = NULL;
	session->uri = NULL;
	session->uri_len = 0;
	session->uri_is_dir = false;
	session->parsing_oke = false;
	session->request_uri = NULL;
	session->request_method = unknown;
	session->extension = NULL;
	session->encode_gzip = false;
	session->path_info = NULL;
	session->alias = NULL;
	session->script_alias = NULL;
	session->vars = NULL;
	session->http_version = NULL;
	session->http_headers = NULL;
	session->body = NULL;
	session->local_user = NULL;
	session->header_sent = false;
	session->data_sent = false;
	session->cause_of_30x = missing_slash;
	session->header_length = 0;
	session->content_length = 0;
	session->file_on_disk = NULL;
	session->mimetype = NULL;
	session->hostname = NULL;
	session->host = session->config->first_host;
	session->host_copied = false;
	session->throttle = 0;
	session->throttle_timer = 0;
	session->bytecounter = 0;
	session->part_of_dirspeed = false;
	session->remote_user = NULL;
	session->http_auth = no_auth;
	session->directory = NULL;
	session->handling_error = false;
	session->reason_for_403 = "";
	session->cookies = NULL;
	session->bytes_sent = 0;
	session->output_size = 0;
	session->return_code = 200;
	session->error_cause = ec_NONE;
	session->error_code = -1;
	session->log_request = true;
	session->tempdata = NULL;
	session->uploaded_file = NULL;
	session->location = NULL;
	session->send_date = true;
	session->send_expires = false;
	session->expires = -1;
	session->caco_private = true;
	session->letsencrypt_auth_request = false;
#ifdef ENABLE_TOOLKIT
	session->toolkit_fastcgi = NULL;
#endif
#ifdef ENABLE_DEBUG
	session->current_task = NULL;
#endif
}

/* Initialize a session-record.
 */
void init_session(t_session *session) {
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_CLIENT);
#endif
	if ((session->client_id = new_client_id++) == MAX_CHILD_ID) {
		new_client_id = 0;
	}
	session->request_limit = true;
	session->force_quit = false;
	session->keep_alive = false;
	session->kept_alive = 0;

	session->last_host = NULL;
	session->request = NULL;
	session->buffer_size = 0;
	session->bytes_in_buffer = 0;

	clear_session(session);

	session->socket_open = false;
	session->via_trusted_proxy = false;
	session->flooding_timer = session->time;

#ifdef ENABLE_RPROXY
	session->rproxy_kept_alive = false;
#endif
}

/* Reset a session-record for reuse.
 */
void reset_session(t_session *session) {
	long size;

	check_clear_free(session->file_on_disk, CHECK_USE_STRLEN);
#ifdef CIFS
	check_free(session->extension);
#endif
	check_clear_free(session->local_user, CHECK_USE_STRLEN);
	check_clear_free(session->remote_user, CHECK_USE_STRLEN);
	check_free(session->path_info);
	check_free(session->request_uri);
	check_free(session->location);
	if (session->uploaded_file != NULL) {
		unlink(session->uploaded_file);
		free(session->uploaded_file);
	}
	session->http_headers = remove_http_headers(session->http_headers);
	if (session->directory != NULL) {
		pthread_mutex_lock(&(session->directory->client_mutex));
		if (session->part_of_dirspeed) {
			if (--session->directory->nr_of_clients == 0) {
				session->directory->session_speed = session->directory->upload_speed;
			} else {
				session->directory->session_speed = session->directory->upload_speed / session->directory->nr_of_clients;
			}
		}
		pthread_mutex_unlock(&(session->directory->client_mutex));
	}

#ifdef ENABLE_TOOLKIT
	if (session->host->toolkit_rules_user != NULL) {
		free(session->host->toolkit_rules_user);
	}

	remove_charlist(&(session->host->toolkit_rules_user_str));
#endif

	/* HTTP pipelining
	 */
	size = session->header_length + session->content_length;
	if ((session->bytes_in_buffer > size) && session->keep_alive) {
		session->bytes_in_buffer -= size;
		memmove(session->request, session->request + size, session->bytes_in_buffer);
		*(session->request + session->bytes_in_buffer) = '\0';
	} else {
		check_clear_free(session->request, session->buffer_size);
		session->request = NULL;
		session->buffer_size = 0;
		session->bytes_in_buffer = 0;
	}

	remove_tempdata(session->tempdata);
	if (session->host_copied) {
		free(session->host);
	}

	clear_session(session);
}

/* Free all remaining buffers
 */
void destroy_session(t_session *session) {
#ifdef ENABLE_RPROXY
	if (session->rproxy_kept_alive) {
#ifdef ENABLE_TLS
		if (session->rproxy_use_tls) {
			tls_close(&(session->rproxy_ssl));
		}
#endif
		close(session->rproxy_socket);
		session->rproxy_kept_alive = false;
	}
#endif

	check_free(session->request);
	session->request = NULL;
}

/* Determine the request method
 */
void determine_request_method(t_session *session) {
	if (strncmp(session->request, "GET ", 4) == 0) {
		session->request_method = GET;
	} else if (strncmp(session->request, "POST ", 5) == 0) {
		session->request_method = POST;
	} else if (strncmp(session->request, "BREW ", 5) == 0) {
		session->request_method = POST;
	} else if (strncmp(session->request, "HEAD ", 5) == 0) {
		session->request_method = HEAD;
	} else if (strncmp(session->request, "TRACE ", 6) == 0) {
		session->request_method = TRACE;
	} else if (strncmp(session->request, "PUT ", 4) == 0) {
		session->request_method = PUT;
	} else if (strncmp(session->request, "DELETE ", 7) == 0) {
		session->request_method = DELETE;
	} else if (strncmp(session->request, "CONNECT ", 8) == 0) {
		session->request_method = CONNECT;
	} else if (strncmp(session->request, "WHEN ", 5) == 0) {
		session->request_method = WHEN;
	} else if (strncmp(session->request, "OPTIONS ", 8) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "PROPFIND ", 9) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "PROPPATCH ", 10) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "MKCOL ", 6) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "COPY ", 5) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "MOVE ", 5) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "LOCK ", 5) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "UNLOCK ", 7) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "REPORT ", 7) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "PATCH ", 6) == 0) {
		session->request_method = unsupported;
	} else if (strncmp(session->request, "MKCALENDAR ", 11) == 0) {
		session->request_method = unsupported;
	}
}

/* Get the extension of the file to be processed
 */
int get_target_extension(t_session *session) {
	char *last_slash;

#ifdef CIFS
	check_free(session->extension);
	session->extension = NULL;
#endif

	if ((last_slash = strrchr(session->file_on_disk, '/')) == NULL) {
		return -1;
	}

	if ((session->extension = strrchr(last_slash, '.')) != NULL) {
		session->extension++;
	} else if (session->letsencrypt_auth_request == false) {
		session->extension = session->host->no_extension_as;
	}

#ifdef CIFS
	if (session->extension != NULL) {
		if ((session->extension = strdup(session->extension)) == NULL) {
			return -1;
		}
		strlower(session->extension);
	}
#endif

	return 0;
}

/* Return the path of the user's homedirectory.
 */
int get_homedir(t_session *session, char *username) {
	struct passwd *pwd;
	size_t len;
	char *old_root;

	if (username == NULL) {
		return 500;
	} else if ((pwd = getpwnam(username)) == NULL) {
		return 404;
	}

	old_root = session->host->website_root;

	len = strlen(pwd->pw_dir) + strlen(session->config->user_directory) + 1;
	if ((session->host->website_root = (char*)malloc(len + 1)) == NULL) {
		session->host->website_root = old_root;
		return -1;
	}

	sprintf(session->host->website_root, "%s/%s", pwd->pw_dir, session->config->user_directory);
	if (register_tempdata(&(session->tempdata), session->host->website_root, tc_data) == -1) {
		free(session->host->website_root);
		session->host->website_root = old_root;
		return -1;
	}
	session->host->website_root_len = strlen(session->host->website_root);

	return 200;
}

/* Duplicate the active host-record. The duplicate can now savely be altered
 * and will be used during the session.
 */
bool duplicate_host(t_session *session) {
	t_host *new_host;

	if ((session->host != NULL) && (session->host_copied == false)) {
		if ((new_host = (t_host*)malloc(sizeof(t_host))) == NULL) {
			return false;
		}

		memcpy(new_host, session->host, sizeof(t_host));
		new_host->next = NULL;
		session->host = new_host;
		session->host_copied = true;
	}

	return true;
}

#ifdef ENABLE_TOOLKIT
int load_user_root_config(t_session *session) {
	char *conffile;
	int result;

	if ((conffile = malloc(session->host->website_root_len + 11)) == NULL) {
		return -1;
	}

	memcpy(conffile, session->host->website_root, session->host->website_root_len);
	memcpy(conffile + session->host->website_root_len, "/.hiawatha\0", 11);

	if ((result = read_user_configfile(conffile, session->host, &(session->tempdata), only_root_config)) != 0) {
		log_error_file(session, conffile, "error in configuration file on line %d", result);
		result = -1;
	}

	free(conffile);

	if (toolkit_rules_str_to_ptr(session->config->url_toolkit, &(session->host->toolkit_rules_user_str), &(session->host->toolkit_rules_user)) == -1) {
		result = -1;
	}

	return result;
}
#endif

/* Load configfile from directories
 */
int load_user_config(t_session *session) {
	char *search, *conffile;
	size_t length;
	int result;
	t_user_config_mode read_mode;

	if (session->file_on_disk == NULL) {
		return 0;
	} else if ((length = strlen(session->file_on_disk)) <= 1) {
		return 0;
	} else if ((conffile = (char*)malloc(length + 10)) == NULL) {
		return -1;
	}

	search = session->file_on_disk + 1;
	while (*search != '\0') {
		if (*search == '/') {
			length = search - session->file_on_disk + 1;

			if (length - 1 != session->host->website_root_len) {
				read_mode = non_root_config;
			} else if (memcmp(session->file_on_disk, session->host->website_root, length - 1) != 0) {
				read_mode = non_root_config;
			} else {
				read_mode = ignore_root_config;
			}

			memcpy(conffile, session->file_on_disk, length);
			memcpy(conffile + length, ".hiawatha\0", 10);
			result = read_user_configfile(conffile, session->host, &(session->tempdata), read_mode);

			if (result != 0) {
				log_error_file(session, conffile, "error in configuration file on line %d", result);
				free(conffile);
				return -1;
			}
		}

		search++;
	}

	free(conffile);

	return 0;
}

/* Copy the settings from a directory-record to the active host-record.
 */
int copy_directory_settings(t_session *session) {
	size_t path_length;
	t_directory *dir;
	int d, p;

	if (session->host->directory == NULL) {
		return 200;
	}

	for (d = 0; session->host->directory[d] != NULL; d++) {
		dir = session->host->directory[d];

		for (p = 0; p < dir->path.size; p++) {
			path_length = strlen(dir->path.item[p]);

			if (strncmp(session->request_uri, dir->path.item[p], path_length) != 0) {
				continue;
			}

			if (dir->path.item[p][strlen(dir->path.item[p]) - 1] != '/') {
				if (*(session->request_uri + path_length) != '/') {
					continue;
				}
			}

			if ((session->extension != NULL) && dir->extensions.size > 0) {
				if (session->uri_len > 0 ? session->uri[session->uri_len - 1] != '/' : false) {
					if (in_charlist(session->extension, &(dir->extensions)) == false) {
						continue;
					}
				}
			}

			session->directory = dir;

			if (dir->max_clients > -1) {
				pthread_mutex_lock(&(dir->client_mutex));
				if (dir->nr_of_clients < dir->max_clients) {
					session->throttle = dir->session_speed = dir->upload_speed / ++dir->nr_of_clients;
					pthread_mutex_unlock(&(dir->client_mutex));
					session->part_of_dirspeed = true;
				} else {
					pthread_mutex_unlock(&(dir->client_mutex));
					return 503;
				}
			}
			if (dir->wrap_cgi != NULL) {
				session->host->wrap_cgi = dir->wrap_cgi;
			}
			if (dir->start_file != NULL) {
				session->host->start_file = dir->start_file;
			}
			if (dir->execute_cgi_set) {
				session->host->execute_cgi = dir->execute_cgi;
			}
#ifdef ENABLE_XSLT
			if (dir->show_index_set) {
				session->host->show_index = dir->show_index;
			}
#endif
			if (dir->follow_symlinks_set) {
				session->host->follow_symlinks = dir->follow_symlinks;
			}
			if (dir->access_list != NULL) {
				session->host->access_list = dir->access_list;
			}
			if (dir->alter_list != NULL) {
				session->host->alter_list = dir->alter_list;
			}
			if (dir->alter_fmode != 0) {
				session->host->alter_fmode = dir->alter_fmode;
			}
			if (dir->passwordfile != NULL) {
				session->host->auth_method = dir->auth_method;
				session->host->passwordfile = dir->passwordfile;
				if (dir->groupfile != NULL) {
					session->host->groupfile = dir->groupfile;
				}
			}
			if (dir->required_group.size > 0) {
				session->host->required_group.size = dir->required_group.size;
				session->host->required_group.item = dir->required_group.item;
			}
			if (dir->alter_group.size > 0) {
				session->host->alter_group.size = dir->alter_group.size;
				session->host->alter_group.item = dir->alter_group.item;
			}
			if (dir->time_for_cgi > TIMER_OFF) {
				session->host->time_for_cgi = dir->time_for_cgi;
			}
			if (dir->expires > -1) {
				session->expires = dir->expires;
				session->caco_private = dir->caco_private;
			}

			break;
		}
	}

	return 200;
}

/* Remove port from hostname
 */
int remove_port_from_hostname(t_session *session) {
	char *c, *hostname;

	if (session->hostname == NULL) {
		return -1;
	}

#ifdef ENABLE_IPV6
	if (session->binding->interface.family == AF_INET6) {
		if ((*(session->hostname) == '[') && ((c = strchr(session->hostname, ']')) != NULL)) {
			c++;

			if (*c == ':') {
				if ((hostname = strdup(session->hostname)) == NULL) {
					return -1;
				} else if (register_tempdata(&(session->tempdata), hostname, tc_data) == -1) {
					free(hostname);
					return -1;
				}

				*(hostname + (c - session->hostname)) = '\0';
				session->hostname = hostname;
			}

			return 0;
		}
	}
#endif

	if ((c = strrchr(session->hostname, ':')) != NULL) {
		if (c == session->hostname) {
			return 0;
		}

		if ((hostname = strdup(session->hostname)) == NULL) {
			return -1;
		} else if (register_tempdata(&(session->tempdata), hostname, tc_data) == -1) {
			free(hostname);
			return -1;
		}

		*(hostname + (c - session->hostname)) = '\0';
		session->hostname = hostname;
	}

	return 0;
}

/* Prevent cross-site scripting.
 */

static int prevent_xss_str(t_session *session, char *input) {
	int result = 0;
	short low, high;
	char *str, value;
	char tag[22];

	str = input;

	while (*str != '\0') {
		if ((value = *str) == '%') {
			if ((high = hex_char_to_int(*(str + 1))) != -1) {
				if ((low = hex_char_to_int(*(str + 2))) != -1) {
					value = (char)(high<<4) + low;
					str += 2;
				}
			}
		}

		if (value == '<') {
			str++;
			strncpy(tag, str, 21);
			tag[21] = '\0';
			url_decode(tag);
			strlower(tag);

			if ((memcmp(tag, "script", 6) == 0) && ((tag[6] == ' ') || (tag[6] == '>'))) {
				log_exploit_attempt(session, "XSS", input);
#ifdef ENABLE_TOMAHAWK
				increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_count_exploit_attempt(session);
					monitor_event("XSS attempt for %s%s", session->host->hostname.item[0], session->uri);
				}
#endif

				if (session->host->prevent_xss == p_prevent) {
					*str = '_';
				}

				result = 1;

				break;
			}
		}

		str++;
	}

	return result;
}

int prevent_xss(t_session *session) {
	int result = 0;

	if (session->vars != NULL) {
		result += prevent_xss_str(session, session->vars);
	}

	if ((session->body != NULL) && session->request_limit) {
		result += prevent_xss_str(session, session->body);
	}

	return result;
}

/* Initialize SQL injection detection
 */
int init_sqli_detection(void) {
	t_sqli_pattern *prev;
	int i;

	for (i = 0; sqli_detection[i].text != NULL; i++) {
		prev = sqli_patterns;
		if ((sqli_patterns = (t_sqli_pattern*)malloc(sizeof(t_sqli_pattern))) == NULL) {
			return -1;
		}
		sqli_patterns->next = prev;

		if (regcomp(&(sqli_patterns->regex), sqli_detection[i].text, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
			fprintf(stderr, "Error in regexp %s\n", sqli_detection[i].text);
			return -1;
		}
	}

	return 0;
}

static void log_sqli_attempt(t_session *session, char *str) {
	log_exploit_attempt(session, "SQLi", str);
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled) {
		monitor_count_exploit_attempt(session);
		monitor_event("SQLi attempt for %s%s", session->host->hostname.item[0], session->uri);
	}
#endif
}

/* Prevent SQL injection
 */
static int prevent_sqli_str(t_session *session, char *str, int length) {
	char *data, *c, *begin, *end;
	t_sqli_pattern *pattern;
	int result = 0, i;

	if ((str == NULL) || (length <= 0)) {
		return 0;
	}

	if ((data = (char*)malloc(length + 1)) == NULL) {
		return -1;
	}

	memcpy(data, str, length);
	for (i = 0; i < length; i++) {
		if (data[i] == '\0') {
			data[i] = ' ';
		} else if (strncmp(data + i, "%00", 3) == 0) {
			data[i + 1] = '2';
		}
	}
	data[length] = '\0';

	url_decode(data);

	c = data;
	while (*c != '\0') {
		if (*c == '+') {
			*c = ' ';
		}
		c++;
	}

	/* Remove comments
	 */
	end = data;
	while ((begin = strstr(end, "/*")) != NULL) {
		if ((end = strstr(begin + 2, "*/")) == NULL) {
			break;
		}
		end += 2;
		if (*(begin + 2) != '!') {
			memset(begin, ' ', end - begin);
		}
	}

	/* Remove double parenthesis
	 */
	end = data;
	while ((begin = strchr(end, '(')) != NULL) {
		end = begin + 1;
		while (*end == ' ') {
			end++;
		}
		if (*end == '(') {
			*begin = ' ';
		}
	}

	/* SQL operators
	 */
	if ((c = strchr(data, '\'')) != NULL) {
		do {
			c++;
		} while ((*c == ' ') || (*c == '\t'));

		for (i = 0; sql_operators[i].text != NULL; i++) {
			if (strncasecmp(c, sql_operators[i].text, strlen(sql_operators[i].text)) == 0) {
				log_sqli_attempt(session, str);
				result = 1;
				goto sqli_done;
			}
		}
	}

	/* Match patterns
	 */
	pattern = sqli_patterns;
	while (pattern != NULL) {
		if (regexec(&(pattern->regex), data, 0, NULL, 0) != REG_NOMATCH) {
			log_sqli_attempt(session, str);
			result = 1;
			goto sqli_done;
		}

		pattern = pattern->next;
	}

sqli_done:
	free(data);

	return result;
}

int prevent_sqli(t_session *session) {
	int result;

	if (session->request_limit == false) {
		return 0;
	}

	if (session->request_uri != NULL) {
		if ((result = prevent_sqli_str(session, session->request_uri, strlen(session->request_uri))) != 0) {
			return result;
		}
	}

	if (session->body != NULL) {
		if ((result = prevent_sqli_str(session, session->body, session->content_length)) != 0) {
			return result;
		}
	}

	if (session->cookies != NULL) {
		if ((result = prevent_sqli_str(session, session->cookies, strlen(session->cookies))) != 0) {
			return result;
		}
	}

	return 0;
}

/* Prevent Cross-site Request Forgery
 */
int prevent_csrf(t_session *session) {
	char *referer, *slash, prev = '\0';
	int i, n;
#ifdef ENABLE_MONITOR
	char *csrf_url;
#endif

	if (session->request_method != POST) {
		return 0;
	}

	if ((referer = get_referer_header(session->http_headers)) == NULL) {
		return 0;
	}

#ifdef ENABLE_MONITOR
	csrf_url = referer;
#endif

	if (strncmp(referer, "http://", 7) == 0) {
		referer += 7;
	} else if (strncmp(referer, "https://", 8) == 0) {
		referer += 8;
	} else {
		session->request_method = GET;
		session->body = NULL;
		session->cookies = NULL;

		log_error_session(session, "invalid referer while checking for CSRF");

		return 1;
	}

	if ((slash = strchr(referer, '/')) != NULL) {
		n = slash - referer;
	} else {
		n = strlen(referer);
	}

	for (i = 0; i < session->host->hostname.size; i++) {
		if (strncasecmp(referer, *(session->host->hostname.item + i), n) == 0) {
			return 0;
		}
	}

	if (session->body != NULL) {
		prev = *(session->body + session->content_length);
		*(session->body + session->content_length) = '\0';
	}

	log_exploit_attempt(session, "CSRF", session->body);

	if (session->body != NULL) {
		*(session->body + session->content_length) = prev;
	}

	if (session->host->prevent_csrf == p_prevent) {
		session->request_method = GET;
		session->body = NULL;
		session->cookies = NULL;
	}

#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled) {
		monitor_count_exploit_attempt(session);
		monitor_event("CSRF attempt for %s%s via %s", session->host->hostname.item[0], session->uri, csrf_url);
	}
#endif

	return 1;
}

void close_socket(t_session *session) {
	if (session->socket_open) {
#ifdef ENABLE_TLS
		if (session->binding->use_tls) {
			tls_close(&(session->tls_context));
		}
#endif
		fsync(session->client_socket);
		close(session->client_socket);
		session->socket_open = false;
	}
}

int handle_connection_not_allowed(t_session *session, int connections) {
	switch (connections) {
		case ca_TOOMUCH_PERIP:
			log_system_session(session, "Maximum number of connections for IP address reached");
			if ((session->config->ban_on_max_per_ip > 0) && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				log_system_session(session, "Client banned because of too many simultaneous connections");
				ban_ip(&(session->ip_address), session->config->ban_on_max_per_ip, session->config->kick_on_ban);
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_count_ban(session);
				}
#endif
			}
			return 444;
		case ca_TOOMUCH_TOTAL:
			log_system_session(session, "Maximum number of total connections reached");
			return 503;
		case ca_BANNED:
			if (session->config->reban_during_ban && (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny)) {
				reban_ip(&(session->ip_address));
			}
#ifdef ENABLE_TOMAHAWK
			increment_counter(COUNTER_DENY);
#endif
			return 444;
	}

	return 500;
}

bool file_can_be_compressed(t_session *session) {
	if (session->mimetype != NULL) {
		if (strncmp(session->mimetype, "text/", 5) == 0) {
			return true;
		} else if (strcmp(session->mimetype, "image/svg+xml") == 0) {
			return true;
		}
	}

	return in_charlist(session->extension, &(session->config->gzip_extensions));
}

#ifdef ENABLE_DEBUG
void printhex(char *str, int len) {
	int chars_per_line = 16, i, max_i;

	while (len > 0) {
		max_i = len > chars_per_line ? chars_per_line : len;

		for (i = 0; i < max_i; i++) {
			fprintf(stderr, "%02X ", *((unsigned char*)str + i));
		}
		for (i = max_i; i < chars_per_line; i++) {
			fprintf(stderr, "   ");
		}

		fprintf(stderr, "  ");
		for (i = 0; i < max_i; i++) {
			if ((*((unsigned char*)str + i) >= 32) && (*((unsigned char*)str + i) <= 126)) {
				fprintf(stderr, "%c", *((unsigned char*)str + i));
			} else {
				fprintf(stderr, ".");
			}
		}
		for (i = max_i; i < chars_per_line; i++) {
			fprintf(stderr, " ");
		}

		fprintf(stderr, "\n");

		str += chars_per_line;
		len -= chars_per_line;
	}
}
#endif
