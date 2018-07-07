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
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <regex.h>
#include "serverconfig.h"
#include "libstr.h"
#include "libfs.h"
#include "memdbg.h"

#define ID_NOBODY             65534
#define MAX_LENGTH_CONFIGLINE  1024
#define MAX_CACHE_SIZE         1024
#define MAX_UPLOAD_SIZE        2047
#define MONITOR_HOSTNAME  "monitor"

enum t_section { syntax_error = -1, none, binding, virtual_host, directory, fcgi_server
#ifdef ENABLE_TOOLKIT
	, url_toolkit
#endif
	};

static bool including = false;
static t_keyvalue *variables = NULL;
#ifdef ENABLE_XSLT
static char *index_xslt;
#endif
#ifdef ENABLE_TLS
static t_hpkp_data *hpkp_records = NULL;
#endif

int init_config_module(char *config_dir) {
	size_t config_dir_len;
	char *line;

	config_dir_len = strlen(config_dir);

	/* Set CONFIG_DIR config variable
	 */
	if ((line = (char*)malloc(config_dir_len + 12)) == NULL) {
		return -1;
	}

	snprintf(line, 1024, "CONFIG_DIR=%s", config_dir);
	if (parse_keyvalue(line, &variables, "=") == -1) {
		return -1;
	}

#ifdef ENABLE_XSLT
	/* Set default path to index.xslt
	 */
	index_xslt = line;
	sprintf(index_xslt, "%s/index.xslt", config_dir);
#else
	free(line);
#endif

	return 0;
}

static t_host *new_host(void) {
	t_host *host;

	if ((host = (t_host*)malloc(sizeof(t_host))) == NULL) {
		return NULL;
	}

	host->website_root        = NULL;
	host->website_root_len    = 0;
	host->start_file          = "index.html";
	host->error_handlers      = NULL;
	host->access_logfile      = LOG_DIR"/access.log";
	host->access_fileptr      = NULL;
	host->access_fp           = &(host->access_fileptr);
	host->rotate_access_log   = never;
	host->access_time         = 0;
	host->error_logfile       = LOG_DIR"/error.log";
	init_charlist(&(host->hostname));
	host->user_websites       = false;
	host->execute_cgi         = false;
	host->time_for_cgi        = 5;
	host->no_extension_as     = NULL;
#if defined(ENABLE_XSLT) || defined(ENABLE_MONITOR)
	host->show_index          = NULL;
#endif
#ifdef ENABLE_XSLT
	host->use_xslt            = false;
	host->error_xslt_file     = NULL;
#endif
	host->enforce_first_hostname = false;
	host->allow_dot_files     = false;
	host->access_list         = NULL;
	host->alter_list          = NULL;
	host->alter_fmode         = S_IRUSR | S_IWUSR | S_IRGRP;
	host->run_on_alter        = NULL;
	host->login_message       = "Private page";
	host->passwordfile        = NULL;
	host->groupfile           = NULL;
	init_charlist(&(host->required_binding));
	init_charlist(&(host->required_group));
	init_charlist(&(host->alter_group));
	host->custom_headers_client = NULL;
#ifdef ENABLE_TOOLKIT
	init_charlist(&(host->toolkit_rules_str));
	host->toolkit_rules       = NULL;
	init_charlist(&(host->toolkit_rules_user_str));
	host->toolkit_rules_user  = NULL;
#endif
	host->wrap_cgi            = NULL;
	init_groups(&(host->groups));
	host->imgref_replacement  = NULL;
	host->envir_str           = NULL;
	host->alias               = NULL;
	host->script_alias        = NULL;
#ifdef ENABLE_TLS
	host->require_tls         = false;
	host->hsts_time           = NULL;
	host->key_cert_file       = NULL;
	host->ca_cert_file        = NULL;
	host->ca_crl_file         = NULL;
	host->private_key         = NULL;
	host->certificate         = NULL;
	host->ca_certificate      = NULL;
	host->ca_crl              = NULL;
	host->random_header_length = -1;
	host->hpkp_data           = NULL;
#endif
#ifdef ENABLE_RPROXY
	host->rproxy              = NULL;
	init_charlist(&(host->use_rproxy));
	host->custom_headers_rproxy = NULL;
#endif
	host->prevent_sqli        = p_no;
	host->prevent_xss         = p_no;
	host->prevent_csrf        = p_no;
	host->follow_symlinks     = false;
	host->enable_path_info    = false;
	host->trigger_on_cgi_status = false;
	init_charlist(&(host->directory_str));
	host->directory           = NULL;
	init_charlist(&(host->fcgi_server_str));
	host->fcgi_server         = NULL;
	host->secure_url          = true;
	host->use_local_config    = false;
	host->deny_body           = NULL;
	host->webdav_app          = false;
	host->http_auth_to_cgi    = false;
	host->ban_by_cgi          = false;
	host->ban_by_cgi_max      = -1;
#ifdef ENABLE_MONITOR
	host->monitor_host_stats  = NULL;
	host->monitor_host        = false;
#endif
#ifdef ENABLE_FILEHASHES
	host->file_hashes         = NULL;
#endif
	host->websockets          = NULL;
	init_charlist(&(host->skip_cache_cookies));

	host->next                = NULL;

	return host;
}

static t_directory *new_directory(void) {
	t_directory *directory;

	if ((directory = (t_directory*)malloc(sizeof(t_directory))) == NULL) {
		return NULL;
	}

	directory->dir_id              = NULL;
	init_charlist(&(directory->path));
	init_charlist(&(directory->extensions));
	directory->wrap_cgi            = NULL;
	directory->start_file          = NULL;
	directory->execute_cgi_set     = false;
#ifdef ENABLE_XSLT
	directory->show_index          = NULL;
	directory->show_index_set      = false;
#endif
	directory->follow_symlinks_set = false;
	directory->access_list         = NULL;
	directory->alter_list          = NULL;
	directory->alter_fmode         = 0;
	init_groups(&(directory->groups));
	directory->passwordfile        = NULL;
	directory->groupfile           = NULL;
	init_charlist(&(directory->required_group));
	init_charlist(&(directory->alter_group));
	directory->imgref_replacement  = NULL;
	directory->max_clients         = -1;
	directory->nr_of_clients       = 0;
	directory->upload_speed        = 0;
	directory->session_speed       = 0;
	directory->time_for_cgi        = TIMER_OFF;
	directory->run_on_download     = NULL;
	directory->expires             = -1;
	directory->caco_private        = true;
	if (pthread_mutex_init(&(directory->client_mutex), NULL) != 0) {
		return NULL;
	}

	directory->next                = NULL;

	return directory;
}

static t_fcgi_server *new_fcgi_server(void) {
	t_fcgi_server *fcgi_server;

	if ((fcgi_server = (t_fcgi_server*)malloc(sizeof(t_fcgi_server))) == NULL) {
		return NULL;
	}

	fcgi_server->fcgi_id          = NULL;
	fcgi_server->connect_to       = NULL;
	fcgi_server->session_timeout  = 900;
	fcgi_server->chroot           = NULL;
	fcgi_server->chroot_len       = 0;
	fcgi_server->localhost        = false;
	init_charlist(&(fcgi_server->extension));

	return fcgi_server;
}

static t_binding *new_binding(void) {
	t_binding *binding;

	if ((binding = (t_binding*)malloc(sizeof(t_binding))) == NULL) {
		return NULL;
	}

	binding->port                 = -1;
	default_ipv4(&(binding->interface));
#ifdef ENABLE_TLS
	binding->use_tls              = false;
	binding->key_cert_file        = NULL;
	binding->ca_cert_file         = NULL;
	binding->ca_crl_file          = NULL;
	binding->tls_config           = NULL;
	binding->private_key          = NULL;
	binding->certificate          = NULL;
	binding->ca_certificate       = NULL;
	binding->ca_crl               = NULL;
#endif
	binding->binding_id           = NULL;
#ifdef HAVE_ACCF
	binding->enable_accf          = false;
#endif
	binding->enable_trace         = false;
	binding->enable_alter         = false;
	binding->max_keepalive        = 50;
	binding->max_request_size     = 64 * KILOBYTE;
	binding->max_upload_size      = MEGABYTE;
	binding->time_for_1st_request = 5;
	binding->time_for_request     = 30;

	binding->socket               = -1;
	binding->poll_data            = NULL;

	binding->next                 = NULL;

	return binding;
}

t_config *default_config(void) {
	t_config *config;
	char *gzip_ext;

	if ((config = (t_config*)malloc(sizeof(t_config))) == NULL) {
		return NULL;
	}

	config->mimetype_config    = "mimetype.conf";

	config->binding            = NULL;
#ifdef ENABLE_TOMAHAWK
	config->tomahawk_port      = NULL;
#endif

	config->server_uid         = (uid_t)ID_NOBODY;
	config->server_gid         = (gid_t)ID_NOBODY;
	config->server_string      = "Hiawatha v"VERSION;
	init_groups(&(config->groups));
	init_charlist(&(config->cgi_extension));
#ifdef ENABLE_THREAD_POOL
	config->thread_pool_size   = 25;
	config->thread_kill_rate   = 1;
#endif
#ifndef CYGWIN
	config->set_rlimits        = true;
#endif
	config->total_connections  = 150;
	config->connections_per_ip = 15;
	config->socket_send_timeout = 3;
	config->listen_backlog     = 16;
	config->kill_timedout_cgi  = true;
	config->wait_for_cgi       = true;
	if ((config->first_host = new_host()) == NULL) {
		free(config);
		return NULL;
	}
	config->mimetype           = NULL;
	config->directory          = NULL;
	config->throttle           = NULL;
	config->cgi_handler        = NULL;
	config->fcgi_server        = NULL;
	config->cgi_wrapper        = SBIN_DIR"/cgi-wrapper";
	config->wrap_user_cgi      = false;
	config->log_format         = hiawatha;
	config->syslog             = SYSLOG_NONE;
	config->log_timeouts       = true;
	config->rotate_access_logs = false;
	config->anonymize_ip       = false;
	config->user_directory     = "public_html";
	config->user_directory_set = false;
	config->hide_proxy         = NULL;
	config->request_limit_mask = NULL;
	config->max_url_length     = 1000;

	config->pidfile            = PID_DIR"/hiawatha.pid";
	config->system_logfile     = LOG_DIR"/system.log";
	config->garbage_logfile    = NULL;
	config->exploit_logfile    = LOG_DIR"/exploit.log";
	config->logfile_mask       = NULL;

	config->ban_on_denied_body = 0;
	config->ban_on_garbage     = 0;
	config->ban_on_max_per_ip  = 2;
	config->ban_on_flooding    = 0;
	config->ban_on_max_request_size = 0;
	config->ban_on_sqli        = 0;
	config->ban_on_timeout     = 0;
	config->ban_on_wrong_password = 0;
	config->ban_on_invalid_url = 0;
	init_charlist(&(config->block_extensions));
	config->kick_on_ban        = false;
	config->reban_during_ban   = false;
	config->max_wrong_passwords = 0;
	config->flooding_count     = 0;
	config->flooding_time      = 0;
	config->reconnect_delay    = 0;
	config->banlist_mask       = NULL;
	config->work_directory     = WORK_DIR;
	config->upload_directory   = NULL;
	config->upload_directory_len = 0;
	config->gzipped_directory  = NULL;
	config->gzipped_directory_len = 0;
	init_charlist(&(config->gzip_extensions));
	if ((gzip_ext = strdup("cer,crt,doc,pem,ppt,ttf,xls,xml,xsl,xslt")) != NULL) {
		parse_charlist(gzip_ext, &(config->gzip_extensions));
		free(gzip_ext);
	}

#ifdef ENABLE_CHALLENGE
	config->challenge_threshold = -1;
	config->challenge_secret   = NULL;
#endif

#ifdef ENABLE_TOOLKIT
	config->url_toolkit        = NULL;
#endif
#ifdef CYGWIN
	config->platform           = windows;
#endif

#ifdef ENABLE_LOADCHECK
	config->max_server_load    = 0;
#endif

#ifdef ENABLE_CACHE
	config->cache_size         = 10 * MEGABYTE;
	config->cache_max_filesize = 256 * KILOBYTE;
#ifdef ENABLE_RPROXY
	init_charlist(&(config->cache_rproxy_extensions));
	config->tunnel_ssh_iplist  = NULL;
	config->tunnel_ssh_credential = NULL;
#endif
#endif

#ifdef ENABLE_TOMAHAWK
	config->tomahawk_port      = NULL;
#endif

#ifdef ENABLE_MONITOR
	config->monitor_enabled    = false;
	config->monitor_directory  = WORK_DIR"/monitor";
#endif

#ifdef ENABLE_TLS
	config->min_tls_version    = MBEDTLS_SSL_MINOR_VERSION_2;
	config->dh_size            = 2048;
	config->ca_certificates    = NULL;
#endif
	return config;
}

static int fgets_multi(char *line, int size, FILE *fp) {
	int lines;
	char *pos;

	if ((line == NULL) || (size <= 1)) {
		return -1;
	} else if (fgets(line, size, fp) != NULL) {
		if ((pos = strstr(line, " \\\n")) == NULL) {
			pos = strstr(line, " \\\r");
		}

		if (pos == NULL) {
			lines = 0;
		} else if ((lines = fgets_multi(pos, size - (pos - line), fp)) == -1) {
			return -1;
		}

		return 1 + lines;
	} else {
		return 0;
	}
}

static bool valid_start_file(char *file) {
	if (file != NULL) {
		if (strchr(file, '/') == NULL) {
			if (strlen(file) <= MAX_START_FILE_LENGTH) {
				return true;
			}
		}
	}

	return false;
}

#ifdef CYGWIN
static bool valid_windows_path(char *path) {
	if (((*path >= 'a') && (*path <= 'z')) || ((*path >= 'A') && (*path <= 'Z'))) {
		if (*(path + 1) == ':') {
			if ((*(path + 2) == '\\') || (*(path + 2) == '/')) {
				return true;
			}
		}
	}

	return false;
}
#endif

static bool valid_path(char *path) {
	if (path == NULL) {
		return false;
	}

	if (*path == '/') {
		return true;
	}

#ifdef CYGWIN
	if (valid_windows_path(path)) {
		return true;
	}
#endif

	return false;
}

static bool valid_directory(char *dir) {
	size_t len;

	if (dir == NULL) {
		return false;
	}

	if ((len = strlen(dir)) <= 1) {
		return false;
	}

	if (valid_path(dir) == false) {
		return false;
	}

	if (*(dir + len - 1) == '/') {
		fprintf(stderr, "- error: trailing slash in %s\n", dir);
		return false;
	}

	return true;
}

static int parse_mode(char *line, mode_t *mode) {
	mode_t mod = 0;
	int i;

	if (strlen(line) != 3) {
		return -1;
	}

	for (i = 0; i < 3; i++) {
		if ((line[i] < '0') || (line[i] > '9')) {
			return -1;
		}
		mod = (8 * mod) + (line[i] - '0');
	}
	*mode = mod;

	return 0;
}

static int parse_prevent(char *prevent, t_prevent *result, t_prevent yes) {
	if ((strcmp(prevent, "no") == 0) || (strcmp(prevent, "false") == 0)) {
		*result = p_no;
	} else if ((strcmp(prevent, "yes") == 0) || (strcmp(prevent, "true") == 0)) {
		*result = yes;
	} else if (strcmp(prevent, "detect") == 0) {
		*result = p_detect;
	} else if (strcmp(prevent, "prevent") == 0) {
		*result = p_prevent;
	} else if (strcmp(prevent, "block") == 0) {
		*result = p_block;
	} else {
		return -1;
	}

	return 0;
}

static int parse_credentialfiles(char *line, t_auth_method *auth_method, char **pwdfile, char **groupfile) {
	char *file, *group;

	split_string(line, &line, &group, ',');
	if (strcasecmp(line, "none") == 0) {
		*pwdfile = NULL;
	} else if (strcmp(line, "") == 0) {
		if (group == NULL) {
			return -1;
		}
	} else {
		if (split_string(line, &line, &file, ':') == -1) {
			return -1;
		}

		strlower(line);
		if (strcmp(line, "basic") == 0) {
			*auth_method = basic;
		} else if (strcmp(line, "digest") == 0) {
			*auth_method = digest;
		} else {
			return -1;
		}

		if ((*pwdfile = strdup(file)) == NULL) {
			return -1;
		}
	}

	if (group != NULL) {
		if ((*groupfile = strdup(group)) == NULL) {
			return -1;
		}
	}

	return 0;
}

static int parse_expires(char *line, int *time, bool *caco_private) {
	char *rest;
	size_t last;

	if (split_string(line, &line, &rest, ' ') == -1) {
		return -1;
	} else if ((*time = str_to_int(line)) == -1) {
		return -1;
	}

	split_string(rest, &line, &rest, ',');

	if ((last = strlen(line)) == 0) {
		return -1;
	}
	last--;
	if (line[last] == 's') {
		line[last] = '\0';
	}

	if (strcasecmp(line, "minute") == 0) {
		*time *= MINUTE;
	} else if (strcasecmp(line, "hour") == 0) {
		*time *= HOUR;
	} else if (strcasecmp(line, "day") == 0) {
		*time *= DAY;
	} else if (strcasecmp(line, "week") == 0) {
		*time *= 7 * DAY;
	} else if (strcasecmp(line, "month") == 0) {
		*time *= 30.5 * DAY;
	} else if (strcasecmp(line, "second") != 0) {
		return -1;
	}

	if (rest != NULL) {
		if (strcasecmp(rest, "public") == 0) {
			*caco_private = false;
		} else if (strcasecmp(rest, "private") == 0) {
			*caco_private = true;
		} else {
			return -1;
		}
	}

	return 0;
}

#ifdef ENABLE_TLS
static int parse_hpkp(char *line, t_hpkp_data **hpkp_data) {
	char *file, *max_age;
	t_hpkp_data *record;
	int max_age_i;
	size_t len;

	if (split_string(line, &file, &max_age, ',') == 0) {
		if ((len = strlen(max_age)) == 0) {
			return -1;
		}

		if ((max_age_i = time_str_to_int(max_age)) == -1) {
			return -1;
		}
	} else {
		max_age_i = 30 * DAY;
	}

	record = hpkp_records;
	while (record != NULL) {
		if ((strcmp(record->cert_file, file) == 0) && (record->max_age == max_age_i)) {
			*hpkp_data = record;
			return 0;
		}

		record = record->next;
	}

	if ((*hpkp_data = (t_hpkp_data*)malloc(sizeof(t_hpkp_data))) == NULL) {
		return -1;
	}

	if (((*hpkp_data)->cert_file = strdup(file)) == NULL) {
		return -1;
	}

	(*hpkp_data)->max_age = max_age_i;
	(*hpkp_data)->http_header = NULL;
	(*hpkp_data)->next = hpkp_records;

	hpkp_records = *hpkp_data;

	return 0;
}
#endif

static bool replace_variables(char **line) {
	bool replaced = false;
	t_keyvalue *variable;
	char *new;

	variable = variables;
	while (variable != NULL) {
		if (str_replace(*line, variable->key, variable->value, &new) > 0) {
			if (replaced) {
				free(*line);
			}
			*line = new;
			replaced = true;
		}
		variable = variable->next;
	}

	return replaced;
}

#ifdef CYGWIN
static int fix_windows_path(char *value, char *key) {
	char *pos;
	size_t len;

	if (key != NULL) {
		if (strcmp(key, "setenv") == 0) {
			return 0;
		}
	}

	if (value == NULL) {
		return -1;
	} else if (strlen(value) + 40 > MAX_LENGTH_CONFIGLINE) {
		return -1;
	}
	if ((pos = strstr(value, ":\\")) == NULL) {
		return 0;
	}
	pos--;
	if (pos > value) {
		if ((*(pos - 1) != ':') && (*(pos - 1) != ',')) {
			return 0;
		}
	} else if (pos != value) {
		return 0;
	}
	if ((*pos >= 'A') && (*pos <= 'Z')) {
		*pos += 32;
	} else if ((*pos < 'a') || (*pos > 'z')) {
		return 0;
	}
	len = strlen(pos) - 2;
	memmove(pos + 12, pos + 3, len);
	*(pos + 10) = *pos;
	*(pos + 11) = '/';
	memcpy(pos, "/cygdrive/", 10);

	pos = pos + 12;
	while (*pos != '\0') {
		if (*pos == '\\') {
			*pos = '/';
		} else if ((*pos == ':') || (*pos == ',')) {
			break;
		}
		pos++;
	}

	return 1;
}
#endif

void close_bindings(t_binding *binding) {
	while (binding != NULL) {
		close(binding->socket);

		binding = binding->next;
	}
}

#ifdef ENABLE_TOOLKIT
int toolkit_rules_str_to_ptr(t_url_toolkit *toolkit_rules, t_charlist *rules_str, t_url_toolkit ***rules_ptr) {
	t_url_toolkit *rule;
	bool found;
	int i;

	if (rules_str == NULL) {
		return 0;
	} else if (rules_str->size == 0) {
		return 0;
	} else if ((*rules_ptr = (t_url_toolkit**)malloc(sizeof(t_url_toolkit*) * (rules_str->size + 1))) == NULL) {
		return -1;
	}

	for (i = 0; i < rules_str->size; i++) {
		rule = toolkit_rules;
		found = false;

		while (rule != NULL) {
			if (strcmp(rules_str->item[i], rule->toolkit_id) == 0) {
				(*rules_ptr)[i] = rule;
				found = true;
				break;
			}

			rule = rule->next;
		}

		if (found == false) {
			return -1;
		}
	}

	(*rules_ptr)[rules_str->size] = NULL;

	return 0;
}
#endif

int check_configuration(t_config *config) {
	t_fcgi_server *fcgi_server;
	t_connect_to *connect_to;
	t_directory *directory;
	t_host *host;
	char c;
	int i;
	size_t len;
	bool found;

	if (config->first_host->hostname.size == 0) {
		fprintf(stderr, "The default website has no hostname.\n");
		return -1;
	}

	if (config->first_host->website_root == NULL) {
		fprintf(stderr, "The default website has no websiteroot.\n");
		return -1;
	}

	len = strlen(config->work_directory);

	config->upload_directory_len = len + 7;
	if ((config->upload_directory = (char*)malloc(config->upload_directory_len + 1)) == NULL) {
		return -1;
	}
	sprintf(config->upload_directory, "%s/upload", config->work_directory);

	config->gzipped_directory_len = len + 8;
	if ((config->gzipped_directory = (char*)malloc(config->gzipped_directory_len + 1)) == NULL) {
		return -1;
	}
	sprintf(config->gzipped_directory, "%s/gzipped", config->work_directory);

#ifdef ENABLE_MONITOR
	if ((config->monitor_directory = (char*)malloc(len + 9)) == NULL) {
		return -1;
	}
	sprintf(config->monitor_directory, "%s/monitor", config->work_directory);

	if ((config->monitor_enabled) && (config->first_host->next != NULL)) {
		host = config->first_host->next;
		if (strcmp(host->hostname.item[0], MONITOR_HOSTNAME) == 0) {
			host->website_root = config->monitor_directory;
			host->website_root_len = strlen(host->website_root);
		}
	}
#endif

	host = config->first_host;
	while (host != NULL) {
		for (i = 0; i < host->hostname.size; i++) {
			if (strchr(*(host->hostname.item + i), '/') != NULL) {
				fprintf(stderr, "The hostname '%s' contains a path.\n", *(host->hostname.item + i));
				return -1;
			}
		}

		if (host->rotate_access_log != never) {
			config->rotate_access_logs = true;
		}

		host = host->next;
	}

	/* FastCGI configuration
	 */
	fcgi_server = config->fcgi_server;
	while (fcgi_server != NULL) {
		fcgi_server->localhost = true;
		connect_to = fcgi_server->connect_to;
		while (connect_to != NULL) {
			if (connect_to->localhost == false) {
				fcgi_server->localhost = false;
				break;
			}
			connect_to = connect_to->next;
		}

		connect_to = fcgi_server->connect_to;
		while (connect_to->next != NULL) {
			connect_to = connect_to->next;
		}
		connect_to->next = fcgi_server->connect_to;

		host = config->first_host;
		if ((fcgi_server->chroot != NULL) && (fcgi_server->chroot_len > 0)) {
			while (host != NULL) {
				if (host->fcgi_server_str.size != 0) {
					if (in_charlist(fcgi_server->fcgi_id, &(host->fcgi_server_str))) {
						/* FastCGIid match
						 */
						if (strncmp(fcgi_server->chroot, host->website_root, fcgi_server->chroot_len) == 0) {
							c = host->website_root[fcgi_server->chroot_len];
							if ((c == '/') || (c == '\0')) {
								goto next_host;
							}
						}

						fprintf(stderr, "The ServerRoot of FastCGI server '%s' is not located with the DocumentRoot of virtual host '%s'.\n", fcgi_server->fcgi_id, *(host->hostname.item));
						return -1;
					}
				}

next_host:
				host = host->next;
			}
		}

		fcgi_server = fcgi_server->next;
	}

	host = config->first_host;
	while (host != NULL) {
		if (host->fcgi_server_str.size > 0) {
			if ((host->fcgi_server = (t_fcgi_server**)malloc(sizeof(t_fcgi_server*) * (host->fcgi_server_str.size + 1))) == NULL) {
				return -1;
			}

			for (i = 0; i < host->fcgi_server_str.size; i++) {
				fcgi_server = config->fcgi_server;
				found = false;

				while (fcgi_server != NULL) {
					if (strcmp(host->fcgi_server_str.item[i], fcgi_server->fcgi_id) == 0) {
						host->fcgi_server[i] = fcgi_server;
						found = true;
						break;
					}

					fcgi_server = fcgi_server->next;
				}

				if (found == false) {
					fprintf(stderr, "FastCGI server '%s' not found.\n", host->fcgi_server_str.item[i]);
					return -1;
				}
			}

			host->fcgi_server[host->fcgi_server_str.size] = NULL;
		}

		host = host->next;
	}

	/* Directory configration
	 */
	host = config->first_host;
	while (host != NULL) {
		if (host->directory_str.size > 0) {
			if ((host->directory = (t_directory**)malloc(sizeof(t_directory*) * (host->directory_str.size + 1))) == NULL) {
				return -1;
			}

			for (i = 0; i < host->directory_str.size; i++) {
				directory = config->directory;
				found = false;

				while (directory != NULL) {
					if (strcmp(host->directory_str.item[i], directory->dir_id) == 0) {
						host->directory[i] = directory;
						found = true;
						break;
					}

					directory = directory->next;
				}

				if (found == false) {
					fprintf(stderr, "Directory '%s' not found.\n", host->directory_str.item[i]);
					return -1;
				}
			}

			host->directory[host->directory_str.size] = NULL;
		}

		host = host->next;
	}

	/* URL Toolkit configuration
	 */
#ifdef ENABLE_TOOLKIT
	if (toolkit_rules_oke(config->url_toolkit) == false) {
		return -1;
	}

	host = config->first_host;
	while (host != NULL) {
		if (toolkit_rules_str_to_ptr(config->url_toolkit, &(host->toolkit_rules_str), &(host->toolkit_rules)) == -1) {
			return -1;
		}

		host = host->next;
	}
#endif

	if (config->binding == NULL) {
		fprintf(stderr, "No binding defined.\n");
		return -1;
	}

	if ((config->first_host->required_binding.size > 0)
#ifdef ENABLE_TLS
		|| (config->first_host->require_tls == true)
#endif
	) {
		fprintf(stderr,
#ifdef ENABLE_TLS
			"RequireTLS and "
#endif
			"RequiredBinding not allowed outside VirtualHost section.\n");
		return -1;
	}

	return 0;
}

static bool system_setting(char *key, char *value, t_config *config) {
	char *uid, *gid, *rest;
	t_cgi_handler *cgi;
	t_throttle *throt;
	int speed, result;
#ifdef ENABLE_TOMAHAWK
	t_binding *binding;
	char *port, *password;
#endif
#ifdef ENABLE_MONITOR
	t_host *monitor_host;
	char *alist;
#endif

	if (strcmp(key, "anonymizeip") == 0) {
		if (parse_yesno(value, &(config->anonymize_ip)) == 0) {
			return true;
		}
	} else if (strcmp(key, "banlistmask") == 0) {
		if ((config->banlist_mask = parse_accesslist(value, false, config->banlist_mask)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "banondeniedbody") == 0) {
		if ((config->ban_on_denied_body = time_str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonflooding") == 0) {
		if (split_string(value, &value, &rest, '/') == -1) {
		} else if ((config->flooding_count = str_to_int(value)) <= 0) {
		} else if (split_string(rest, &value, &rest, ':') != 0) {
		} else if ((config->flooding_time = time_str_to_int(value)) <= 0) {
		} else if ((config->ban_on_flooding = str_to_int(rest)) > 0) {
			return true;
		}
	} else if (strcmp(key, "banongarbage") == 0) {
		if ((config->ban_on_garbage = time_str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banoninvalidurl") == 0) {
		if ((config->ban_on_invalid_url = time_str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonmaxperip") == 0) {
		if ((config->ban_on_max_per_ip = time_str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonmaxreqsize") == 0) {
		if ((config->ban_on_max_request_size = time_str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonsqli") == 0) {
		if ((config->ban_on_sqli = time_str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banontimeout") == 0) {
		if ((config->ban_on_timeout = time_str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "banonwrongpassword") == 0) {
		if (split_string(value, &value, &rest, ':') == -1) {
		} else if ((config->max_wrong_passwords = str_to_int(value)) <= 0) {
		} else if ((config->ban_on_wrong_password = time_str_to_int(rest)) > 0) {
			return true;
		}
	} else if (strcmp(key, "blockextensions") == 0) {
		if (parse_charlist(value, &(config->block_extensions)) == 0) {
			return true;
		}
#ifdef ENABLE_TLS
	} else if (strcmp(key, "cacertificates") == 0) {
		if (tls_load_ca_root_certs(value, &(config->ca_certificates)) == 0) {
			return true;
		}
#endif
#ifdef ENABLE_CACHE
	} else if (strcmp(key, "cachemaxfilesize") == 0) {
		if ((config->cache_max_filesize = str_to_int(value)) != -1) {
			config->cache_max_filesize <<= 10 /* convert to kB */;
			return true;
		}
#ifdef ENABLE_RPROXY
	} else if (strcmp(key, "cacherproxyextensions") == 0) {
		if (parse_charlist(value, &(config->cache_rproxy_extensions)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "cachesize") == 0) {
		if ((config->cache_size = str_to_int(value)) != -1) {
			if (config->cache_size <= MAX_CACHE_SIZE) {
				config->cache_size <<= 20 /* convert to MB */;
				return true;
			}
		}
#endif
	} else if (strcmp(key, "cgiextension") == 0) {
#ifdef CIFS
		strlower(value);
#endif
		if (parse_charlist(value, &(config->cgi_extension)) == 0) {
			return true;
		}
	} else if (strcmp(key, "cgihandler") == 0) {
#ifdef CYGWIN
		if (valid_windows_path(value)) {
			result = split_string(value + 2, &value, &rest, ':');
			value -= 2;
		} else
#endif
			result = split_string(value, &value, &rest, ':');

		if (result == 0) {
			if ((*value != '\0') && (*rest != '\0')) {
				cgi = config->cgi_handler;
				if ((config->cgi_handler = (t_cgi_handler*)malloc(sizeof(t_cgi_handler))) != NULL) {
					config->cgi_handler->next = cgi;
					if ((config->cgi_handler->handler = strdup(value)) != NULL) {
#ifdef CIFS
						strlower(rest);
#endif
						init_charlist(&(config->cgi_handler->extension));
						if (parse_charlist(rest, &(config->cgi_handler->extension)) == 0) {
							return true;
						}
					}
				}
			}
		}
	} else if (strcmp(key, "cgiwrapper") == 0) {
		if ((config->cgi_wrapper = strdup(value)) != NULL) {
			return true;
		}
#ifdef ENABLE_CHALLENGE
	} else if (strcmp(key, "challengeclient") == 0) {
		if (split_string(value, &value, &rest, ',') != 0) {
			return false;
		} else if ((config->challenge_threshold = str_to_int(value)) == -1) {
			return false;
		}

		if (split_string(rest, &value, &rest, ',') == -1) {
			return false;
		} else if (strcmp(value, "httpheader") == 0) {
			config->challenge_mode = cm_httpheader;
		} else if (strcmp(value, "javascript") == 0) {
			config->challenge_mode = cm_javascript;
		} else {
			return false;
		}

		split_string(rest, &value, &rest, ',');
		if ((config->challenge_ban = str_to_int(value)) >= 0) {
			if (rest != NULL) {
				if ((config->challenge_secret = strdup(rest)) == NULL) {
					return false;
				}
			}
			return true;
		}
#endif
	} else if (strcmp(key, "connectionsperip") == 0) {
		if ((config->connections_per_ip = str_to_int(value)) > 0) {
			return true;
		}
	} else if (strcmp(key, "connectionstotal") == 0) {
		if ((config->total_connections = str_to_int(value)) > 0) {
			return true;
		}

#ifdef ENABLE_TLS
	} else if (strcmp(key, "dhsize") == 0) {
		if (strcmp(value, "2048") == 0) {
			config->dh_size = 2048;
			return true;
		} else if (strcmp(value, "4096") == 0) {
			config->dh_size = 4096;
			return true;
		} else if (strcmp(value, "8192") == 0) {
			config->dh_size = 8192;
			return true;
		}
#endif
	} else if (strcmp(key, "exploitlogfile") == 0) {
		if (valid_path(value)) {
			if ((config->exploit_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "garbagelogfile") == 0) {
		if (valid_path(value)) {
			if ((config->garbage_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "gzipextensions") == 0) {
		if (parse_charlist(value, &(config->gzip_extensions)) == 0) {
			return true;
		}
	} else if (strcmp(key, "hideproxy") == 0) {
		if (parse_iplist(value, &(config->hide_proxy)) != -1) {
			return true;
		}
	} else if (strcmp(key, "kickonban") == 0) {
		if (parse_yesno(value, &(config->kick_on_ban)) == 0) {
			return true;
		}
	} else if (strcmp(key, "killtimedoutcgi") == 0) {
		if (parse_yesno(value, &(config->kill_timedout_cgi)) == 0) {
			return true;
		}
	} else if (strcmp(key, "listenbacklog") == 0) {
		if ((config->listen_backlog = str_to_int(value)) >= 1) {
			return true;
		}
	} else if (strcmp(key, "logformat") == 0) {
		if (strcmp(value, "hiawatha") == 0) {
			config->log_format = hiawatha;
			return true;
		} else if (strcmp(value, "common") == 0) {
			config->log_format = common;
			return true;
		} else if (strcmp(value, "extended") == 0) {
			config->log_format = extended;
			return true;
		}
	} else if (strcmp(key, "logfilemask") == 0) {
		if ((config->logfile_mask = parse_accesslist(value, false, config->logfile_mask)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "logtimeouts") == 0) {
		if (parse_yesno(value, &(config->log_timeouts)) == 0) {
			return true;
		}
#ifdef ENABLE_LOADCHECK
	} else if (strcmp(key, "maxserverload") == 0) {
		if ((config->max_server_load = atof(value)) > 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "maxurllength") == 0) {
		if (strcasecmp(value, "none") == 0) {
			config->max_url_length = 0;
			return true;
		} else if ((config->max_url_length = str_to_int(value)) >= 0) {
			return true;
		}
	} else if (strcmp(key, "mimetypeconfig") == 0) {
		if ((config->mimetype_config = strdup(value)) != NULL) {
			return true;
		}
#ifdef ENABLE_TLS
	} else if (strcmp(key, "mintlsversion") == 0) {
		if ((strcmp(value, "1.0") == 0) || (strcmp(value, "TLS1.0") == 0)) {
			config->min_tls_version = MBEDTLS_SSL_MINOR_VERSION_1;
			return true;
		} else if ((strcmp(value, "1.1") == 0) || (strcmp(value, "TLS1.1") == 0)) {
			config->min_tls_version = MBEDTLS_SSL_MINOR_VERSION_2;
			return true;
		} else if ((strcmp(value, "1.2") == 0) || (strcmp(value, "TLS1.2") == 0)) {
			config->min_tls_version = MBEDTLS_SSL_MINOR_VERSION_3;
			return true;
		}
#endif
#ifdef ENABLE_MONITOR
	} else if (strcmp(key, "monitorserver") == 0) {
		if ((monitor_host = new_host()) == NULL) {
			return false;
		}
		monitor_host->next = config->first_host->next;
		config->first_host->next = monitor_host;

		if (parse_charlist(MONITOR_HOSTNAME, &(monitor_host->hostname)) == -1) {
			return false;
		}

		monitor_host->website_root = config->monitor_directory;
		monitor_host->website_root_len = strlen(monitor_host->website_root);
		monitor_host->access_logfile = NULL;
		monitor_host->error_logfile = NULL;

		rest = "allow %s, deny all";
		if ((alist = (char*)malloc(strlen(rest) + strlen(value) + 1)) == NULL) {
			return false;
		}
		sprintf(alist, rest, value);
		if ((monitor_host->access_list = parse_accesslist(alist, false, NULL)) == NULL) {
			return false;
		}
		free(alist);

#if defined(ENABLE_XSLT) || defined(ENABLE_MONITOR)
		if ((monitor_host->show_index = strdup("xml")) == NULL) {
			return false;
		}
#endif

		monitor_host->monitor_host = true;
		config->monitor_enabled = true;

		return true;
#endif
	} else if (strcmp(key, "pidfile") == 0) {
		if (valid_path(value)) {
			if ((config->pidfile = strdup(value)) != NULL) {
				return true;
			}
		}
#ifdef CYGWIN
	} else if (strcmp(key, "platform") == 0) {
		if (strcmp(value, "windows") == 0) {
			config->platform = windows;
			return true;
		} else if (strcmp(value, "cygwin") == 0) {
			config->platform = cygwin;
			return true;
		}
#endif
	} else if (strcmp(key, "rebanduringban") == 0) {
		if (parse_yesno(value, &(config->reban_during_ban)) == 0) {
			return true;
		}
	} else if (strcmp(key, "reconnectdelay") == 0) {
		if ((config->reconnect_delay = str_to_int(value)) >= 0) {
			return true;
		}
	} else if (strcmp(key, "requestlimitmask") == 0) {
		if ((config->request_limit_mask = parse_accesslist(value, false, config->request_limit_mask)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "serverid") == 0) {
		split_string(value, &uid, &gid, ':');
		if (parse_userid(uid, &(config->server_uid)) == 1) {
			if (gid != NULL) {
				if (parse_groups(gid, &(config->server_gid), &(config->groups)) == 1) {
					return true;
				}
			} else {
				if (lookup_group_ids(config->server_uid, &(config->server_gid), &(config->groups)) == 1) {
					return true;
				}
			}
		}
	} else if (strcmp(key, "serverstring") == 0) {
		if ((strcasecmp(value, "none") == 0) || (strcasecmp(value, "null") == 0)) {
			config->server_string = NULL;
			return true;
		} else if (strlen(value) < 128) {
			if ((config->server_string = strdup(remove_spaces(value))) != NULL) {
				return true;
			}
		}
#ifndef CYGWIN
	} else if (strcmp(key, "setresourcelimits") == 0) {
		if (parse_yesno(value, &(config->set_rlimits)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "socketsendtimeout") == 0) {
		if ((config->socket_send_timeout = str_to_int(value)) >= 0) {
			return true;
		}
	} else if (strcmp(key, "syslog") == 0) {
		rest = value;
		do {
			split_string(rest, &value, &rest, ',');
			if (strcmp(value, "system") == 0) {
				config->syslog |= SYSLOG_SYSTEM;
			} else if (strcmp(value, "exploit") == 0) {
				config->syslog |= SYSLOG_EXPLOIT;
			} else if (strcmp(value, "garbage") == 0) {
				config->syslog |= SYSLOG_GARBAGE;
			} else if (strcmp(value, "access") == 0) {
				config->syslog |= SYSLOG_ACCESS;
			} else if (strcmp(value, "error") == 0) {
				config->syslog |= SYSLOG_ERROR;
			} else if (strcmp(value, "all") == 0) {
				config->syslog |= SYSLOG_ALL;
			} else {
				return false;
			}
		} while (rest != NULL);
		return true;
	} else if (strcmp(key, "systemlogfile") == 0) {
		if (valid_path(value)) {
			if ((config->system_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
#ifdef ENABLE_THREAD_POOL
	} else if (strcmp(key, "threadkillrate") == 0) {
		if ((config->thread_kill_rate = str_to_int(value)) >= 1) {
			return true;
		}
	} else if (strcmp(key, "threadpoolsize") == 0) {
		if ((config->thread_pool_size = str_to_int(value)) >= 1) {
			return true;
		}
#endif
	} else if (strcmp(key, "throttle") == 0) {
		if (split_string(value, &rest, &value, ':') != -1) {
			if (((*rest == '.') || (strchr(rest, '/') != NULL)) && (speed = str_to_int(value)) > 0) {
				if (config->throttle == NULL) {
					if ((config->throttle = (t_throttle*)malloc(sizeof(t_throttle))) == NULL) {
						return false;
					}
					throt = config->throttle;
				} else {
					throt = config->throttle;
					while (throt->next != NULL) {
						throt = throt->next;
					}
					if ((throt->next = (t_throttle*)malloc(sizeof(t_throttle))) == NULL) {
						return false;
					}
					throt = throt->next;
				}
				throt->next = NULL;

				if ((throt->filetype = strlower(strdup(rest))) != NULL) {
					throt->upload_speed = speed << 10; /* convert to kB/s */
					return true;
				}
			}
		}
#ifdef ENABLE_TOMAHAWK
	} else if (strcmp(key, "tomahawk") == 0) {
		if (split_string(value, &port, &password, ',') == 0) {
			if ((binding = new_binding()) == NULL) {
				return false;
			}
			set_to_localhost(&(binding->interface));

			binding->next = config->tomahawk_port;
			config->tomahawk_port = binding;

			if ((config->tomahawk_port->port = str_to_int(port)) > 0) {
				if ((config->tomahawk_port->binding_id = strdup(password)) != NULL) {
					return true;
				}
			} else {
				free(config->tomahawk_port);
			}
		}
#endif
#ifdef ENABLE_RPROXY
	} else if (strcmp(key, "tunnelssh") == 0) {
		split_string(value, &value, &rest, ';');
		if (parse_iplist(value, &(config->tunnel_ssh_iplist)) == -1) {
			if (rest != NULL) {
				return false;
			}
		} else if (rest == NULL) {
			return true;
		} else {
			value = rest;
		}

		if ((config->tunnel_ssh_credential = (char*)malloc(7 + strlen(value))) == NULL) {
			return false;
		}
		sprintf(config->tunnel_ssh_credential, "Basic %s", value);

		return true;

#endif
	} else if (strcmp(key, "userdirectory") == 0) {
		if ((*value != '/') && (strchr(value, '.') == NULL)) {
			if ((config->user_directory = strdup(value)) != NULL) {
				config->user_directory_set = true;
				return true;
			}
		}
	} else if (strcmp(key, "waitforcgi") == 0) {
		if (parse_yesno(value, &(config->wait_for_cgi)) == 0) {
			return true;
		}
	} else if (strcmp(key, "workdirectory") == 0) {
		if (valid_directory(value) == false) {
			return false;
		}

		if (strchr(value + 1, '/') == NULL) {
#ifdef CYGWIN
			if (strchr(value + 1, '\\') == NULL) {
				return false;
			}
#endif
		}

		if ((config->work_directory = strdup(value)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "wrapusercgi") == 0) {
		if (parse_yesno(value, &(config->wrap_user_cgi)) == 0) {
			return true;
		}
	}

	return false;
}

#ifdef ENABLE_TOOLKIT
static bool user_root_setting(char *key, char *value, t_host *host) {
	if (strcmp(key, "usetoolkit") == 0) {
		if (parse_charlist(value, &(host->toolkit_rules_user_str)) != 0) {
			return false;
		}
	}

	return true;
}
#endif

static bool user_setting(char *key, char *value, t_host *host, t_tempdata **tempdata) {
	char *pwd = NULL, *grp = NULL;
	t_error_handler *handler;
	t_keyvalue *kv;

	if (strcmp(key, "accesslist") == 0) {
		if ((host->access_list = parse_accesslist(value, true, host->access_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altergroup") == 0) {
		if (parse_charlist(value, &(host->alter_group)) == 0) {
			return true;
		}
	} else if (strcmp(key, "alterlist") == 0) {
		if ((host->alter_list = parse_accesslist(value, true, host->alter_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altermode") == 0) {
		if (parse_mode(value, &(host->alter_fmode)) != -1) {
			return true;
		}
	} else if (strcmp(key, "errorhandler") == 0) {
		if (parse_error_handler(value, &(host->error_handlers)) == -1) {
			return false;
		}

		if (register_tempdata(tempdata, host->error_handlers, tc_errorhandler) == -1) {
			handler = host->error_handlers;
			host->error_handlers = host->error_handlers->next;
			remove_error_handler(handler);
			return false;
		}

		return true;
	} else if (strcmp(key, "loginmessage") == 0) {
		if (strlen(value) < 64) {
			if ((host->login_message = strdup(value)) != NULL) {
				if (register_tempdata(tempdata, host->login_message, tc_data) != -1) {
					return true;
				} else {
					free(host->login_message);
					host->login_message = NULL;
				}
			}
		}
	} else if (strcmp(key, "passwordfile") == 0) {
		if (parse_credentialfiles(value, &(host->auth_method), &pwd, &grp) == 0) {
			if (pwd != NULL) {
				if (register_tempdata(tempdata, pwd, tc_data) == -1) {
					free(pwd);
					if (grp != NULL) {
						free(grp);
					}
					return false;
				}
			}
			host->passwordfile = pwd;

			if (grp != NULL) {
				if (register_tempdata(tempdata, grp, tc_data) == -1) {
					free(grp);
					return false;
				}
				host->groupfile = grp;
			}
			return true;
		}
	} else if (strcmp(key, "requiredgroup") == 0) {
		if (parse_charlist(value, &(host->required_group)) == 0) {
			return true;
		}
	} else if (strcmp(key, "runonalter") == 0) {
		if ((host->run_on_alter = strdup(value)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "setenv") == 0) {
		if (parse_keyvalue(value, &(host->envir_str), "=") != -1) {
			if (register_tempdata(tempdata, host->envir_str, tc_keyvalue) != -1) {
				return true;
			} else {
				kv = host->envir_str;
				host->envir_str = host->envir_str->next;
				free(kv->key);
				free(kv->value);
				free(kv);
			}
		}
#ifdef ENABLE_XSLT
	} else if (strcmp(key, "showindex") == 0) {
		if (strcmp(value, "yes") == 0) {
			host->show_index = index_xslt;
			return true;
		} else if (strcmp(value, "no") == 0) {
			host->show_index = NULL;
			return true;
		} else if (valid_path(value) || (strcmp(value, "xml") == 0)) {
			if ((host->show_index = strdup(value)) != NULL) {
				return true;
			}
		}
#endif
	} else if (strcmp(key, "startfile") == 0) {
		if (valid_start_file(value)) {
			if ((value = strdup(value)) != NULL) {
				if (register_tempdata(tempdata, value, tc_data) != -1) {
					host->start_file = value;
					return true;
				} else {
					free(value);
				}
			}
		}
	}

	return false;
}

static bool host_setting(char *key, char *value, t_host *host) {
	t_deny_body *deny_body;
	char *rest;
	t_websocket *websocket, *ws;
#ifdef ENABLE_RPROXY
	t_rproxy *rproxy, *list;
#endif
#ifdef ENABLE_TLS
	int time;
	size_t size;
#endif
	int sqli_return_code;

	if (strcmp(key, "accesslogfile") == 0) {
		if (strcasecmp(value, "none") == 0) {
			host->access_logfile = NULL;
			return true;
		} else {
			split_string(value, &value, &rest, ',');
			if (valid_path(value)) {
				if ((host->access_logfile = strdup(value)) != NULL) {
					if (rest != NULL) {
						if (strcasecmp(rest, "daily") == 0) {
							host->rotate_access_log = daily;
						} else if (strcasecmp(rest, "weekly") == 0) {
							host->rotate_access_log = weekly;
						} else if (strcasecmp(rest, "monthly") == 0) {
							host->rotate_access_log = monthly;
						} else {
							return false;
						}
					}
					return true;
				}
			}
		}
	} else if (strcmp(key, "alias") == 0) {
		if (parse_keyvalue(value, &(host->alias), ":") != -1) {
			if (valid_directory(host->alias->key) && valid_directory(host->alias->value)) {
				return true;
			}
		}
	} else if (strcmp(key, "allowdotfiles") == 0) {
		if (parse_yesno(value, &(host->allow_dot_files)) == 0) {
			return true;
		}
	} else if (strcmp(key, "banbycgi") == 0) {
		split_string(value, &value, &rest, ',');
		if (parse_yesno(value, &(host->ban_by_cgi)) == 0) {
			if (rest != NULL) {
				if ((host->ban_by_cgi_max = time_str_to_int(rest)) > 0) {
					return true;
				}
			} else {
				return true;
			}
		}
#ifdef ENABLE_RPROXY
	} else if (strcmp(key, "customheaderbackend") == 0) {
		if (parse_keyvalue(value, &(host->custom_headers_rproxy), ":") != -1) {
			return true;
		}
#endif
	} else if ((strcmp(key, "customheaderclient") == 0) || (strcmp(key, "customheader") == 0)) {
		if (parse_keyvalue(value, &(host->custom_headers_client), ":") != -1) {
			return true;
		}
	} else if (strcmp(key, "denybody") == 0) {
		if (host->deny_body == NULL) {
			host->deny_body = (t_deny_body*)malloc(sizeof(t_deny_body));
			deny_body = host->deny_body;
		} else {
			deny_body = host->deny_body;
			while (deny_body->next != NULL) {
				deny_body = deny_body->next;
			}
			deny_body->next = (t_deny_body*)malloc(sizeof(t_deny_body));
			deny_body = deny_body->next;
		}
		if (deny_body != NULL) {
			deny_body->next = NULL;
			if (regcomp(&(deny_body->pattern), value, REG_EXTENDED | REG_ICASE | REG_NOSUB) == 0) {
				return true;
			}
		}
	} else if (strcmp(key, "enablepathinfo") == 0) {
		if (parse_yesno(value, &(host->enable_path_info)) == 0) {
			return true;
		}
	} else if (strcmp(key, "enforcefirsthostname") == 0) {
		if (parse_yesno(value, &(host->enforce_first_hostname)) == 0) {
			return true;
		}
	} else if (strcmp(key, "errorlogfile") == 0) {
		if (valid_path(value)) {
			if ((host->error_logfile = strdup(value)) != NULL) {
				return true;
			}
		}
#ifdef ENABLE_XSLT
	} else if (strcmp(key, "errorxsltfile") == 0) {
		if (valid_path(value)) {
			if ((host->error_xslt_file = strdup(value)) != NULL) {
				return true;
			}
		}
#endif
	} else if (strcmp(key, "executecgi") == 0) {
		if (parse_yesno(value, &(host->execute_cgi)) == 0) {
			return true;
		}
#ifdef ENABLE_FILEHASHES
	} else if (strcmp(key, "filehashes") == 0) {
		if ((host->file_hashes = read_file_hashes(value)) != NULL) {
			return true;
		}
#endif
	} else if (strcmp(key, "followsymlinks") == 0) {
		if (parse_yesno(value, &(host->follow_symlinks)) == 0) {
			return true;
		}
	} else if (strcmp(key, "hostname") == 0) {
		strlower(value);
#ifdef ENABLE_MONITOR
		if (strcmp(value, MONITOR_HOSTNAME) == 0) {
			return false;
		}
#endif
		if (parse_charlist(value, &(host->hostname)) == 0) {
			return true;
		}
	} else if (strcmp(key, "httpauthtocgi") == 0) {
		if (parse_yesno(value, &(host->http_auth_to_cgi)) == 0) {
			return true;
		}
	} else if (strcmp(key, "noextensionas") == 0) {
		if ((host->no_extension_as = strdup(value)) != NULL) {
			return true;
		}
	} else if ((strcmp(key, "preventcsrf") == 0) || (strcmp(key, "preventxsrf") == 0)) {
		if (parse_prevent(value, &(host->prevent_csrf), p_prevent) == 0) {
			return true;
		}
	} else if (strcmp(key, "preventsqli") == 0) {
		split_string(value, &value, &rest, ',');
		if (parse_prevent(value, &(host->prevent_sqli), p_block) == 0) {
			if ((rest != NULL) && (host->prevent_sqli != p_no)) {
				sqli_return_code = str_to_int(rest);
				if ((sqli_return_code == 403) || (sqli_return_code == 404)) {
					host->prevent_sqli = p_prevent;
				} else if (sqli_return_code == 441) {
					host->prevent_sqli = p_block;
					return true;
				}
			} else {
				return true;
			}
		}
	} else if (strcmp(key, "preventxss") == 0) {
		if (parse_prevent(value, &(host->prevent_xss), p_prevent) == 0) {
			return true;
		}
#ifdef ENABLE_TLS
	} else if (strcmp(key, "publickeypins") == 0) {
		if (parse_hpkp(value, &(host->hpkp_data)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "requiredbinding") == 0) {
		if (parse_charlist(value, &(host->required_binding)) == 0) {
			return true;
		}
#ifdef ENABLE_TLS
	} else if (strcmp(key, "randomheader") == 0) {
		if ((host->random_header_length = str_to_int(value)) >= 10) {
			if (host->random_header_length <= MAX_RANDOM_HEADER_LENGTH) {
				return true;
			}
		}
	} else if (strcmp(key, "requiredca") == 0) {
		split_string(value, &value, &rest, ',');
		if ((host->ca_cert_file = strdup(value)) != NULL) {
			if (rest != NULL) {
				if ((host->ca_crl_file = strdup(rest)) == NULL) {
					return false;
				}
			}
			return true;
		}
	} else if (strcmp(key, "requiretls") == 0) {
		split_string(value, &value, &rest, ',');
		if (parse_yesno(value, &(host->require_tls)) != 0) {
			return false;
		}

		if (rest != NULL) {
			if ((size = strlen(rest)) == 0) {
				return false;
			}

			if ((host->hsts_time = (char*)malloc(size + 10)) == NULL) {
				return false;
			}

			if ((value = strchr(rest, ';')) != NULL) {
				*value = '\0';
				value++;
			}

			rest = remove_spaces(rest);
			if ((size = strlen(rest)) == 0) {
				return false;
			}
			if ((time = time_str_to_int(rest)) <= 0) {
				return false;
			}
			time = sprintf(host->hsts_time, "%d", time);

			if (value != NULL) {
				sprintf(host->hsts_time + time, ";%s", value);

				if ((rest = strchr(value, ';')) != NULL) {
					*rest = '\0';
					rest++;
					rest = remove_spaces(rest);
				}
				value = remove_spaces(value);

				if (strcasecmp(value, "includeSubDomains") == 0) {
					value = rest;
				}

				if (value != NULL) {
					if (strcasecmp(value, "preload") != 0) {
						return false;
					}
				}
			}
		}
		return true;
#endif
#ifdef ENABLE_RPROXY
	} else if (strcmp(key, "reverseproxy") == 0) {
		if ((rproxy = rproxy_setting(value)) != NULL) {
			if (host->rproxy == NULL) {
				host->rproxy = rproxy;
				return true;
			} else {
				list = host->rproxy;
				while (list->next != NULL) {
					list = list->next;
				}
				list->next = rproxy;
				return true;
			}
		}
#endif
	} else if (strcmp(key, "scriptalias") == 0) {
		if (parse_keyvalue(value, &(host->script_alias), ":") != -1) {
			if (valid_directory(host->script_alias->key) && valid_directory(host->script_alias->value)) {
				return true;
			}
		}
	} else if (strcmp(key, "secureurl") == 0) {
		if (parse_yesno(value, &(host->secure_url)) == 0) {
			return true;
		}
	} else if (strcmp(key, "skipcachecookie") == 0) {
		if (parse_charlist(value, &(host->skip_cache_cookies)) == 0) {
			return true;
		}
#ifdef ENABLE_TLS
	} else if (strcmp(key, "tlscertfile") == 0) {
		if ((host->key_cert_file = strdup(value)) != NULL) {
			return true;
		}
#endif
	} else if (strcmp(key, "timeforcgi") == 0) {
		if ((host->time_for_cgi = str_to_int(value)) > TIMER_OFF) {
			return true;
		}
	} else if (strcmp(key, "triggeroncgistatus") == 0) {
		if (parse_yesno(value, &(host->trigger_on_cgi_status)) == 0) {
			return true;
		}
	} else if (strcmp(key, "usedirectory") == 0) {
		if (parse_charlist(value, &(host->directory_str)) == 0) {
			return true;
		}
	} else if (strcmp(key, "usefastcgi") == 0) {
		if (parse_charlist(value, &(host->fcgi_server_str)) == 0) {
			host->execute_cgi = true;
			return true;
		}
	} else if (strcmp(key, "uselocalconfig") == 0) {
		if (parse_yesno(value, &(host->use_local_config)) == 0) {
			return true;
		}
#ifdef ENABLE_RPROXY
	} else if (strcmp(key, "userproxy") == 0) {
		if (parse_charlist(value, &(host->use_rproxy)) == 0) {
			return true;
		}
#endif
#ifdef ENABLE_TOOLKIT
	} else if (strcmp(key, "usetoolkit") == 0) {
		if (parse_charlist(value, &(host->toolkit_rules_str)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "userwebsites") == 0) {
		if (parse_yesno(value, &(host->user_websites)) == 0) {
			return true;
		}
#ifdef ENABLE_XSLT
	} else if (strcmp(key, "usexslt") == 0) {
		if (parse_yesno(value, &(host->use_xslt)) == 0) {
			return true;
		}
#endif
	} else if (strcmp(key, "webdavapp") == 0) {
		if (parse_yesno(value, &(host->webdav_app)) == 0) {
			if (host->webdav_app) {
				host->execute_cgi = true;
			}
			return true;
		}
	} else if (strcmp(key, "websiteroot") == 0) {
		if (valid_directory(value)) {
			if ((host->website_root = strdup(value)) != NULL) {
				host->website_root_len = strlen(host->website_root);
				return true;
			}
		}
	} else if (strcmp(key, "websocket") == 0) {
		if ((websocket = (t_websocket*)malloc(sizeof(t_websocket))) == NULL) {
			return false;
		}

		init_charlist(&(websocket->path));
		websocket->timeout = 10 * MINUTE;
		websocket->next = NULL;

		if (host->websockets == NULL) {
			host->websockets = websocket;
		} else {
			ws = host->websockets;
			while (ws->next != NULL) {
				ws = ws->next;
			}
			ws->next = websocket;
		}

		if (split_string(value, &value, &rest, ' ') != 0) {
			return false;
		}

		if (strncmp(value, "/", 1) == 0) {
			if ((websocket->unix_socket = strdup(value)) == NULL) {
				return false;
			}
#ifdef ENABLE_TLS
			websocket->use_tls = false;
#endif
		} else {
			websocket->unix_socket = NULL;

			if (strncmp(value, "ws://", 5) == 0) {
				value += 5;
#ifdef ENABLE_TLS
				websocket->use_tls = false;
			} else if (strncmp(value, "wss://", 6) == 0) {
				value += 6;
				websocket->use_tls = true;
#endif
			} else {
				return false;
			}

			if (parse_ip_port(value, &(websocket->ip_address), &(websocket->port)) != 0) {
				return false;
			}
		}

		split_string(rest, &value, &rest, ' ');
		if (parse_charlist(value, &(websocket->path)) == 0) {
			if (rest == NULL) {
				return true;
			} else if ((websocket->timeout = str_to_int(rest)) > 0) {
				websocket->timeout *= MINUTE;
				return true;
			}
		}
	} else if (strcmp(key, "wrapcgi") == 0) {
		if ((host->wrap_cgi = strdup(value)) != NULL) {
			return true;
		}
	}

	return false;
}

static bool directory_setting(char *key, char *value, t_directory *directory) {
	char *maxclients;

	if (strcmp(key, "accesslist") == 0) {
		if ((directory->access_list = parse_accesslist(value, true, directory->access_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altergroup") == 0) {
		if (parse_charlist(value, &(directory->alter_group)) == 0) {
			return true;
		}
	} else if (strcmp(key, "alterlist") == 0) {
		if ((directory->alter_list = parse_accesslist(value, true, directory->access_list)) != NULL) {
			return true;
		}
	} else if (strcmp(key, "altermode") == 0) {
		if (parse_mode(value, &(directory->alter_fmode)) != -1) {
			return true;
		}
	} else if (strcmp(key, "directoryid") == 0) {
		if (directory->dir_id == NULL) {
			if ((directory->dir_id = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "executecgi") == 0) {
		if (parse_yesno(value, &(directory->execute_cgi)) == 0) {
			directory->execute_cgi_set = true;
			return true;
		}
	} else if (strcmp(key, "expireperiod") == 0) {
		if (parse_expires(value, &(directory->expires), &(directory->caco_private)) == 0) {
			return true;
		}
	} else if (strcmp(key, "extensions") == 0) {
		if (parse_charlist(value, &(directory->extensions)) == 0) {
			return true;
		}
	} else if (strcmp(key, "followsymlinks") == 0) {
		if (parse_yesno(value, &(directory->follow_symlinks)) == 0) {
			directory->follow_symlinks_set = true;
			return true;
		}
	} else if (strcmp(key, "passwordfile") == 0) {
		if (parse_credentialfiles(value, &(directory->auth_method), &(directory->passwordfile), &(directory->groupfile)) == 0) {
			return true;
		}
	} else if (strcmp(key, "path") == 0) {
		if (parse_charlist(value, &(directory->path)) == 0) {
			return true;
		}
	} else if (strcmp(key, "requiredgroup") == 0) {
		if (parse_charlist(value, &(directory->required_group)) == 0) {
			return true;
		}
	} else if (strcmp(key, "runondownload") == 0) {
		if ((directory->run_on_download = strdup(value)) != NULL) {
			return true;
		}
#ifdef ENABLE_XSLT
	} else if (strcmp(key, "showindex") == 0) {
		if (strcmp(value, "yes") == 0) {
			directory->show_index = index_xslt;
			directory->show_index_set = true;
			return true;
		} else if (strcmp(value, "no") == 0) {
			directory->show_index = NULL;
			directory->show_index_set = true;
			return true;
		} else if (valid_path(value) || (strcmp(value, "xml") == 0)) {
			if ((directory->show_index = strdup(value)) != NULL) {
				directory->show_index_set = true;
				return true;
			}
		}
#endif
	} else if (strcmp(key, "startfile") == 0) {
		if (valid_start_file(value)) {
			if ((directory->start_file = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "timeforcgi") == 0) {
		if ((directory->time_for_cgi = str_to_int(value)) > TIMER_OFF) {
			return true;
		}
	} else if (strcmp(key, "uploadspeed") == 0) {
		if (split_string(value, &value, &maxclients, ',') == 0) {
			if ((directory->upload_speed = str_to_int(value)) > 0) {
				directory->upload_speed <<= 10 /* convert to kB/s */;
				if ((directory->max_clients = str_to_int(maxclients)) > 0) {
					return true;
				}
			}
		}
	} else if (strcmp(key, "wrapcgi") == 0) {
		if ((directory->wrap_cgi = strdup(value)) != NULL) {
			return true;
		}
	}

	return false;
}

static bool binding_setting(char *key, char *value, t_binding *binding) {
	char *rest;

#ifdef HAVE_ACCF
	if (strcmp(key, "enableaccf") == 0) {
		if (parse_yesno(value, &(binding->enable_accf)) == 0) {
			return true;
		}
	} else
#endif
	if (strcmp(key, "enablealter") == 0) {
		if (parse_yesno(value, &(binding->enable_alter)) == 0) {
			return true;
		}
	} else if (strcmp(key, "enabletrace") == 0) {
		if (parse_yesno(value, &(binding->enable_trace)) == 0) {
			return true;
		}
	} else if (strcmp(key, "interface") == 0) {
		if (parse_ip(value, &(binding->interface)) != -1) {
			return true;
		}
	} else if (strcmp(key, "maxkeepalive") == 0) {
		if ((binding->max_keepalive = str_to_int(value)) != -1) {
			return true;
		}
	} else if (strcmp(key, "maxrequestsize") == 0) {
		if ((binding->max_request_size = str_to_int(value)) > 0) {
			binding->max_request_size <<= 10 /* convert to kB */;
			return true;
		}
	} else if (strcmp(key, "maxuploadsize") == 0) {
		if ((binding->max_upload_size = str_to_int(value)) > 0) {
			if (binding->max_upload_size <= MAX_UPLOAD_SIZE) {
				binding->max_upload_size <<= 20 /* convert to MB */;
				return true;
			}
		}
	} else if (strcmp(key, "bindingid") == 0) {
		if (binding->binding_id == NULL) {
			if ((binding->binding_id = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "port") == 0) {
		if ((binding->port = str_to_int(value)) > 0) {
			if (binding->port < 65536) {
				return true;
			}
		}
#ifdef ENABLE_TLS
	} else if (strcmp(key, "requiredca") == 0) {
		split_string(value, &value, &rest, ',');
		if ((binding->ca_cert_file = strdup(value)) != NULL) {
			if (rest != NULL) {
				if ((binding->ca_crl_file = strdup(rest)) == NULL) {
					return false;
				}
			}
			return true;
		}
	} else if (strcmp(key, "tlscertfile") == 0) {
		if ((binding->key_cert_file = strdup(value)) != NULL) {
			binding->use_tls = true;
			return true;
		}
#endif
	} else if (strcmp(key, "timeforrequest") == 0) {
		if (split_string(value, &value, &rest, ',') == 0) {
			if ((binding->time_for_1st_request = str_to_int(value)) >= 1) {
				if ((binding->time_for_request = str_to_int(rest)) >= 1) {
					return true;
				}
			}
		} else if ((binding->time_for_request = str_to_int(value)) >= 1) {
			binding->time_for_1st_request = binding->time_for_request;
			return true;
		}
	}

	return false;
}

static bool fcgi_server_setting(char *key, char *value, t_fcgi_server *fcgi_server) {
	char *rest;
	t_connect_to *connect_to;

	if (strcmp(key, "connectto") == 0) {
		while (value != NULL) {
			split_string(value, &value, &rest, ',');

			if ((connect_to = (t_connect_to*)malloc(sizeof(t_connect_to))) == NULL) {
				return false;
			}
			connect_to->next = fcgi_server->connect_to;
			connect_to->available = true;
			fcgi_server->connect_to = connect_to;

			if (*value == '/') {
				if ((connect_to->unix_socket = strdup(value)) == NULL) {
					return false;
				}
				connect_to->localhost = true;
			} else {
				connect_to->unix_socket = NULL;
				if (parse_ip_port(value, &(connect_to->ip_addr), &(connect_to->port)) == -1) {
					return false;
				}
				connect_to->localhost = false;
			}
			value = rest;
		}
		return true;
	} else if (strcmp(key, "extension") == 0) {
#ifdef CIFS
		strlower(value);
#endif
		if (parse_charlist(value, &(fcgi_server->extension)) == 0) {
			return true;
		}
	} else if (strcmp(key, "fastcgiid") == 0) {
		if (fcgi_server->fcgi_id == NULL) {
			if ((fcgi_server->fcgi_id = strdup(value)) != NULL) {
				return true;
			}
		}
	} else if (strcmp(key, "serverroot") == 0) {
		if ((fcgi_server->chroot = strdup(value)) != NULL) {
			fcgi_server->chroot_len = strlen(fcgi_server->chroot);
			return true;
		}
	} else if (strcmp(key, "sessiontimeout") == 0) {
		if ((fcgi_server->session_timeout = MINUTE * str_to_int(value)) >= 0) {
			return true;
		}
	}

	return false;
}

static int read_config_directory(char *dir, t_config *config, bool config_check) {
	t_filelist *filelist, *file;
	char *path;
	int retval = 0;

	if ((filelist = read_filelist(dir, false)) == NULL) {
		return -1;
	}
	file = filelist = sort_filelist(filelist);

	while (file != NULL) {
		if (strcmp(file->name, "..") != 0) {
			if ((path = make_path(dir, file->name)) != NULL) {
				if (file->is_dir) {
					retval = read_config_directory(path, config, config_check);
				} else {
					retval = read_main_configfile(path, config, config_check);
				}
				free(path);

				if (retval == -1) {
					break;
				}
			} else {
				retval = -1;
				break;
			}
		}
		file = file->next;
	}
	remove_filelist(filelist);

	return retval;
}

int read_main_configfile(char *configfile, t_config *config, bool config_check) {
	int  retval = 0, counter = 0, lines_read;
	FILE *fp;
	char line[MAX_LENGTH_CONFIGLINE + 1], *key, *value;
	bool variables_replaced;
	enum t_section section = none;
	t_host *current_host;
	t_directory *current_directory = NULL;
	t_binding *current_binding = NULL;
	t_fcgi_server *current_fcgi_server = NULL;
#ifdef ENABLE_TOOLKIT
	t_url_toolkit *current_toolkit = NULL;
#endif

	/* Read and parse Hiawatha configurationfile.
	 */
	if ((fp = fopen(configfile, "r")) == NULL) {
		fprintf(stderr, "Can't read file %s.\n", configfile);
		return -1;
	} else if (config_check) {
		printf("Reading %s\n", configfile);
	}

	current_host = config->first_host;
	line[MAX_LENGTH_CONFIGLINE] = '\0';

	while ((lines_read = fgets_multi(line, MAX_LENGTH_CONFIGLINE, fp)) != 0) {
		if ((lines_read == -1) || (strlen(line) > MAX_LENGTH_CONFIGLINE - 1)) {
			retval = counter + 1;
			fprintf(stderr, "Line %d in %s is too long.\n", retval, configfile);
			break;
		}
		counter += lines_read;

		key = uncomment(line);
		if (*key != '\0') {
			variables_replaced = false;

			if (key[strlen(key) - 1] == '{') {
				/* Section start
				 */
				key[strlen(key) - 1] = '\0';
				key = strlower(remove_spaces(key));

				if (section != none) {
					retval = counter;
				} else if (strcmp(key, "binding") == 0) {
					if (config->binding != NULL) {
						current_binding = config->binding;
						while (current_binding->next != NULL) {
							current_binding = current_binding->next;
						}
						if ((current_binding->next = new_binding()) == NULL) {
							perror("new_binding()");
							return -1;
						}
						current_binding = current_binding->next;
					} else {
						if ((config->binding = new_binding()) == NULL) {
							perror("new_binding()");
							return -1;
						}
						current_binding = config->binding;
					}
					section = binding;
				} else if (strcmp(key, "directory") == 0) {
					if (config->directory != NULL) {
						current_directory = config->directory;
						while (current_directory->next != NULL) {
							current_directory = current_directory->next;
						}
						if ((current_directory->next = new_directory()) == NULL) {
							perror("new_directory()");
							return -1;
						}
						current_directory = current_directory->next;
					} else {
						if ((config->directory = new_directory()) == NULL) {
							perror("new_directory()");
							return -1;
						}
						current_directory = config->directory;
					}
					section = directory;
				} else if (strcmp(key, "fastcgiserver") == 0) {
					if ((current_fcgi_server = new_fcgi_server()) == NULL) {
						perror("new_fcgi_server()");
						return -1;
					}
					current_fcgi_server->next = config->fcgi_server;
					config->fcgi_server = current_fcgi_server;
					section = fcgi_server;
				} else if (strcmp(key, "virtualhost") == 0) {
					while (current_host->next != NULL) {
						current_host = current_host->next;
					}
					if ((current_host->next = new_host()) == NULL) {
						perror("new_host()");
						return -1;
					}
					current_host = current_host->next;
					section = virtual_host;
#ifdef ENABLE_TOOLKIT
				} else if (strcmp(key, "urltoolkit") == 0) {
					if ((current_toolkit = new_url_toolkit()) == NULL) {
						perror("new_url_toolkit()");
						return -1;
					}
					current_toolkit->next = config->url_toolkit;
					config->url_toolkit = current_toolkit;
					section = url_toolkit;
#endif
				} else {
					retval = counter;
				}
			} else if (strcmp(key, "}") == 0) {
				/* Section end
				 */
				switch (section) {
					case binding:
						if (current_binding->port == -1) {
							fprintf(stderr, "A Port is missing in a binding section in %s.\n", configfile);
							retval = -1;
						} else {
							current_binding = NULL;
						}
						break;
					case directory:
						if (config->directory->path.size == 0) {
							fprintf(stderr, "A Path is missing in a directory section in %s.\n", configfile);
							retval = -1;
						} else {
							current_directory = NULL;
						}
						break;
					case fcgi_server:
						if ((config->fcgi_server->fcgi_id == NULL) || (config->fcgi_server->connect_to == NULL)) {
							fprintf(stderr, "A FastCGIid or ConnectTo is missing in a FastCGIserver section in %s.\n", configfile);
							retval = -1;
						} else {
							current_fcgi_server = NULL;
						}
						break;
					case virtual_host:
						if (current_host->hostname.size == 0) {
							fprintf(stderr, "A Hostname is missing in a VirtualHost section in %s\n", configfile);
							retval = -1;
						} else if (current_host->website_root == NULL) {
							fprintf(stderr, "A WebsiteRoot is missing for %s in %s\n", current_host->hostname.item[0], configfile);
							retval = -1;
						} else {
							current_host = config->first_host;
						}
						break;
#ifdef ENABLE_TOOLKIT
					case url_toolkit:
						if (current_toolkit->toolkit_id == NULL) {
							fprintf(stderr, "A ToolkitID is missing in a UrlToolkit section in %s\n", configfile);
							retval = -1;
						} else {
							current_toolkit = NULL;
						}
						break;
#endif
					default:
						retval = counter;
				}
				section = none;
			} else if (split_configline(key, &key, &value) != -1) {
				/* Configuration option
				 */
				strlower(key);

				if (strcmp(key, "set") == 0) {
					if (parse_keyvalue(key + 4, &variables, "=") == -1) {
						retval = counter;
					}
				} else if (strcmp(key, "include") == 0) {
					value = key + 8;
#ifdef CYGWIN
					if (fix_windows_path(value, NULL) == -1) {
						retval = counter;
					} else
#endif
					{
						variables_replaced = replace_variables(&value);
						if ((section == none) && (including == false)) {
							including = true;
							switch (file_type(value)) {
								case ft_error:
								case ft_no_access:
								case ft_not_found:
								case ft_other:
									fprintf(stderr, "Error while including '%s'\n", value);
									retval = -1;
									break;
								case ft_file:
									retval = read_main_configfile(value, config, config_check);
									break;
								case ft_dir:
									retval = read_config_directory(value, config, config_check);
									break;
							}
							including = false;
						} else {
							retval = counter;
						}
					}
				} else if (strlen(value) > 0) {
#ifdef CYGWIN
					if (strlen(key) > 25) {
						retval = counter;
					} else if (fix_windows_path(value, key) == -1) {
						retval = counter;
					} else
#endif
					{
						variables_replaced = replace_variables(&value);

						if (section == none) {
							if (system_setting(key, value, config)) {
								goto next_setting;
							}
						}
						if ((section == none) || (section == virtual_host)) {
							if (host_setting(key, value, current_host)) {
								goto next_setting;
							} else if (user_setting(key, value, current_host, NULL)) {
								goto next_setting;
							}
						} else if (section == directory) {
							if (directory_setting(key, value, current_directory)) {
								goto next_setting;
							}
						} else if (section == binding) {
							if (binding_setting(key, value, current_binding)) {
								goto next_setting;
							}
						} else if (section == fcgi_server) {
							if (fcgi_server_setting(key, value, current_fcgi_server)) {
								goto next_setting;
							}
#ifdef ENABLE_TOOLKIT
						} else if (section == url_toolkit) {
							if (toolkit_setting(key, value, current_toolkit)) {
								goto next_setting;
							}
#endif
						}

						retval = counter;
					}
				} else {
					retval = counter;
				}
			} else {
				retval = counter;
			}

next_setting:
			if (variables_replaced) {
				free(value);
			}
		}

		if (retval != 0) {
			break;
		}
	} /* while */

	fclose(fp);
	if (including == false) {
		remove_keyvaluelist(variables);
		variables = NULL;
	}

	if ((retval == 0) && (section != none)) {
		retval = counter;
	}

	if (retval > 0) {
		fprintf(stderr, "Syntax error in %s on line %d.\n", configfile, retval);
		return -1;
	}

	return retval;
}

int read_user_configfile(char *configfile, t_host *host, t_tempdata **tempdata, t_user_config_mode read_mode) {
	int  retval, counter, lines_read;
	FILE *fp;
	char line[MAX_LENGTH_CONFIGLINE + 1], *key, *value;
	t_accesslist *acs_list = NULL, *alt_list = NULL;
	t_charlist req_grp, alt_grp;

	if ((fp = fopen(configfile, "r")) == NULL) {
		return 0;
	}

	line[MAX_LENGTH_CONFIGLINE] = '\0';
	counter = retval = 0;

	if ((tempdata != NULL) && (read_mode != only_root_config)) {
		acs_list = host->access_list;
		host->access_list = NULL;
		alt_list = host->alter_list;
		host->alter_list = NULL;

		copy_charlist(&alt_grp, &(host->alter_group));
		init_charlist(&(host->alter_group));
		copy_charlist(&req_grp, &(host->required_group));
		init_charlist(&(host->required_group));
	}

	while ((lines_read = fgets_multi(line, MAX_LENGTH_CONFIGLINE, fp)) != 0) {
		if ((lines_read == -1) || (strlen(line) > MAX_LENGTH_CONFIGLINE - 1)) {
			retval = counter + 1;
			fprintf(stderr, "Line %d in %s is too long.\n", retval, configfile);
			break;
		}
		counter += lines_read;

		key = uncomment(line);
		if (*key != '\0') {
			if (split_configline(key, &key, &value) != -1) {
				strlower(key);

				if (read_mode == only_root_config) {
#ifdef ENABLE_TOOLKIT
					if (user_root_setting(key, value, host) == false) {
						retval = counter;
						break;
					}
#endif
				} else {
#ifdef ENABLE_TOOLKIT
					if (read_mode == ignore_root_config) {
						if (strcmp(key, "usetoolkit") == 0) {
							continue;
						}
					}
#endif

					if (user_setting(key, value, host, tempdata) == false) {
						retval = counter;
						break;
					}
				}
			} else {
				retval = counter;
				break;
			}
		}
	}

	fclose(fp);

	if ((tempdata != NULL) && (read_mode != only_root_config)) {
		if (host->access_list == NULL) {
			host->access_list = acs_list;
		} else if (register_tempdata(tempdata, host->access_list, tc_accesslist) == -1) {
			remove_accesslist(host->access_list);
			host->access_list = acs_list;
			retval = -1;
		}
		if (host->alter_list == NULL) {
			host->alter_list = alt_list;
		} else if (register_tempdata(tempdata, host->alter_list, tc_accesslist) == -1) {
			remove_accesslist(host->alter_list);
			host->alter_list = alt_list;
			retval = -1;
		}

		if (host->alter_group.size == 0) {
			copy_charlist(&(host->alter_group), &alt_grp);
		} else if (register_tempdata(tempdata, &(host->alter_group), tc_charlist) == -1) {
			remove_charlist(&(host->alter_group));
			copy_charlist(&(host->alter_group), &alt_grp);
			retval = -1;
		}
		if (host->required_group.size == 0) {
			copy_charlist(&(host->required_group), &req_grp);
		} else if (register_tempdata(tempdata, &(host->required_group), tc_charlist) == -1) {
			remove_charlist(&(host->required_group));
			copy_charlist(&(host->required_group), &req_grp);
			retval = -1;
		}
	}

	return retval;
}

t_host *get_hostrecord(t_host *host, char *hostname, t_binding *binding) {
	size_t len_hostname;
	int i;

	if (hostname == NULL) {
		return NULL;
	}

	if ((len_hostname = strlen(hostname)) == 0) {
		return NULL;
	}

	/* Hostname ends with a dot
	 */
	if (hostname[len_hostname - 1] == '.') {
		len_hostname--;
		hostname[len_hostname] = '\0';
	}

	while (host != NULL) {
		if (host->required_binding.size > 0) {
			if (in_charlist(binding->binding_id, &(host->required_binding)) == false) {
				/* Binding not allowed
				 */
				host = host->next;
				continue;
			}
		}

		for (i = 0; i < host->hostname.size; i++) {
			if (hostname_match(hostname, *(host->hostname.item + i))) {
				return host;
			}
		}

		host = host->next;
	}

	return NULL;
}

unsigned short get_throttlespeed(char *type, t_throttle *throttle) {
	t_throttle *throt;
	unsigned long speed = 0;
	int len_type, len_throt;
	char *type_lower;

	if (type == NULL) {
		return 0;
	} else if ((type_lower = strlower(strdup(type))) == NULL) {
		return 0;
	}

	len_type = strlen(type);
	throt = throttle;
	while (throt != NULL) {
		len_throt = strlen(throt->filetype);
		if (len_type >= len_throt) {
			if (memcmp(throt->filetype, type_lower, len_throt) == 0) {
				speed = throt->upload_speed;
				break;
			}
		}
		throt = throt->next;
	}
	free(type_lower);

	return speed;
}
