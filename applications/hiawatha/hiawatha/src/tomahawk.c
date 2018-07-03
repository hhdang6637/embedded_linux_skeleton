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

#ifdef ENABLE_TOMAHAWK

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "global.h"
#include "libstr.h"
#include "tomahawk.h"
#include "log.h"
#include "client.h"
#include "workers.h"
#include "cache.h"
#include "mbedtls/md5.h"
#include "memdbg.h"

#define MAX_IDLE_TIME   60
#define MAX_CMD_SIZE   100
#define TIMESTAMP_SIZE  50

static t_admin *adminlist;
static char *prompt = "\033[01;34mtomahawk>\033[00m ";

static pthread_mutex_t tomahawk_mutex;

static char start_time[TIMESTAMP_SIZE];
extern char *version_string;
extern char *enabled_modules;

static volatile unsigned long counters[COUNTER_MAX];
static volatile unsigned long long transfer[TRANSFER_MAX];

void increment_counter(int counter) {
	counters[counter]++;
}

void increment_transfer(int counter, long bytes) {
	transfer[counter] += bytes;
}

static void clear_counters(void) {
	int i;

	for (i = 0; i < COUNTER_MAX; i++) {
		counters[i] = 0;
	}
	for (i = 0; i < TRANSFER_MAX; i++) {
		transfer[i] = 0;
	}
}

void show_request_to_admins(char *method, char *uri, char *http_version, t_ip_addr *ip_addr,
                            t_http_header *headers, int response_code, off_t bytes_sent) {
	bool generated = false;
	char message[1024], *format, ip_str[MAX_IP_STR_LEN + 1], *hostname, *user_agent;
	t_admin *admin;

	admin = adminlist;
	while (admin != NULL) {
		if (admin->show_requests) {
			if (generated == false) {
				if ((hostname = get_http_header("Host:", headers)) == NULL) {
					hostname = "-";
				}
				if ((user_agent = get_http_header("User-Agent:", headers)) == NULL) {
					user_agent = "-";
				}
				ip_to_str(ip_addr, ip_str, MAX_IP_STR_LEN);

				format = "  %s %s %s\n"
				         "  Host: %s\n"
				         "  Client IP: %s\n"
						 "  User agent: %s\n"
				         "  Result: %d, %ld bytes sent\n\n";
				if (snprintf(message, 1023, format, method, uri, http_version, hostname, ip_str, user_agent, response_code, (long)bytes_sent) > 1023) {
					sprintf(message, "(error generating request information message)\n");
				}
				generated = true;
			}

			fprintf(admin->fp, "%s", message);
			fflush(admin->fp);
		}
		admin = admin->next;
	}
}

/* Initialize Tomahawk
 */
int init_tomahawk_module(void) {
	time_t t;
	struct tm s;

	adminlist = NULL;
	if (pthread_mutex_init(&tomahawk_mutex, NULL) != 0) {
		return -1;
	}

	t = time(NULL);
	localtime_r(&t, &s);
	start_time[TIMESTAMP_SIZE - 1] = '\0';
	strftime(start_time, TIMESTAMP_SIZE - 1, "%a %d %b %Y %T %z", &s);

	clear_counters();

	return 0;
}

/* An administrator has connected to Tomahawk
 */
int add_admin(int sock) {
	t_admin *new;

	if ((new = (t_admin*)malloc(sizeof(t_admin))) == NULL) {
		return -1;
	} else if ((new->fp = fdopen(sock, "r+")) == NULL) {
		free(new);
		return -1;
	}

	fprintf(new->fp, "\n\033[02;31mWelcome to Tomahawk, the Hiawatha command shell\033[00m\n");
	fprintf(new->fp, "Password: \033[00;30;40m"); /* Change color to black */
	fflush(new->fp);

	new->next = adminlist;
	new->socket = sock;
	new->poll_data = NULL;
	new->authenticated = false;
	new->timer = MAX_IDLE_TIME;
	new->show_requests = false;
	adminlist = new;

	return 0;
}

/* Disconnect al the administrators.
 */
void disconnect_admins(void) {
	t_admin *admin;

	pthread_mutex_lock(&tomahawk_mutex);

	while (adminlist != NULL) {
		admin = adminlist;
		adminlist = adminlist->next;

		close(admin->socket);
		free(admin);
	}

	pthread_mutex_unlock(&tomahawk_mutex);
}

/* Check administratos (only auto-logout timers for now).
 */
void check_admin_list(void) {
	t_admin *admin, *prev_admin = NULL, *next_admin;

	pthread_mutex_lock(&tomahawk_mutex);

	admin = adminlist;
	while (admin != NULL) {
		next_admin = admin->next;
		if (admin->timer == 0) {
			fprintf(admin->fp, "\033[00m(auto-logout)\n");
			fflush(admin->fp);
			close(admin->socket);
			if (prev_admin == NULL) {
				adminlist = next_admin;
			} else {
				prev_admin->next = next_admin;
			}
			free(admin);
		} else {
			if (admin->show_requests == false) {
				admin->timer--;
			}
			prev_admin = admin;
		}
		admin = next_admin;
	}

	pthread_mutex_unlock(&tomahawk_mutex);
}

/* Show help info.
 */
static void show_help(FILE *fp) {
	fprintf(fp,	"  ban <ip>[ <time>]: ban an IP (for <time> seconds)\n"
				"  clear screen     : clear the screen\n"
#ifdef ENABLE_CACHE
				"        cache      : remove all unlocked files from the cache\n"
#endif
				"        counters   : set all counters to zero\n"
				"  kick <id>        : kick client by its id (show clients)\n"
				"       <ip>        : kick client by its IP\n"
				"       all         : disconnect all clients\n"
				"  show bans        : show the ban list\n"
#ifdef ENABLE_CACHE
				"       cache       : show the file in the cache\n"
#endif
				"       clients     : show the connected clients\n"
				"       status      : show general information\n"
#ifdef ENABLE_THREAD_POOL
				"       threads     : show thread pool information\n"
#endif
				"  quit/exit        : quit Tomahawk\n"
				"  unban <ip>       : unban an IP address\n"
				"        all        : unban all IP addresses\n");
}

static void show_status(FILE *fp) {
	fprintf(fp, "  %s%s\n", version_string, enabled_modules);
	fprintf(fp, "  Start time        : %s\n\n", start_time);

#ifdef ENABLE_CACHE
	fprintf(fp, "  Size of cache     : %9.1f kB\n", ((float)size_of_cache()) / KILOBYTE);
#endif
	fprintf(fp, "  Number of clients : %7d\n", count_registered_connections());
	fprintf(fp, "  Number of bans    : %7d\n\n", number_of_bans());

	fprintf(fp, "  Clients served    : %7lu\n", counters[COUNTER_CLIENT]);
	fprintf(fp, "  Files requested   : %7lu\n", counters[COUNTER_FILE]);
	fprintf(fp, "  CGIs requested    : %7lu\n", counters[COUNTER_CGI]);
#ifdef ENABLE_XSLT
	fprintf(fp, "  Indexes requested : %7lu\n", counters[COUNTER_INDEX]);
#endif
	fprintf(fp, "  Data received     : %9.1f MB\n", ((float)transfer[TRANSFER_RECEIVED]) / MEGABYTE);
	fprintf(fp, "  Data send         : %9.1f MB\n\n", ((float)transfer[TRANSFER_SEND]) / MEGABYTE);

	fprintf(fp, "  Clients banned    : %7lu\n", counters[COUNTER_BAN]);
	fprintf(fp, "  Connections denied: %7lu\n", counters[COUNTER_DENY]);
	fprintf(fp, "  Exploit attempts  : %7lu\n", counters[COUNTER_EXPLOIT]);
}

#ifdef ENABLE_THREAD_POOL
static void show_thread_pool(FILE *fp) {
	fprintf(fp, "  Thread pool size: %7d\n", count_threads_in_pool());
	fprintf(fp, "  Threads asleep  : %7d\n", count_waiting_workers());
	fprintf(fp, "  Threads quiting : %7d\n", count_threads_marked_quit());
}
#endif

static int run_tomahawk(char *line, t_admin *admin, t_config *config) {
	char *cmd, *param, *param2;
	t_ip_addr ip;
	int retval = 0, timer, id, count;
	FILE *fp;

	fp = admin->fp;

	split_string(line, &cmd, &param, ' ');

	if (strcmp(cmd, "ban") == 0) {
		/* Ban
		 */
		if (param == NULL) {
			fprintf(fp, "  ban what?\n");
		} else {
			if (split_string(param, &param, &param2, ' ') == 0) {
				timer = str_to_int(param2);
			} else {
				timer = TIMER_OFF;
			}
			if (parse_ip(param, &ip) == -1) {
				fprintf(fp, "  invalid IP!\n");
			} else switch (count = ban_ip(&ip, timer, config->kick_on_ban)) {
				case -1:
					fprintf(fp, "  error while banning!\n");
					break;
				case 0:
					fprintf(fp, "  IP rebanned.\n");
					break;
				default:
					fprintf(fp, "  %d IPs banned.", count);
					if (config->kick_on_ban) {
						fprintf(fp, " and kicked\n");
					} else {
						fprintf(fp, "\n");
					}
			}
		}
	} else if (strcmp(cmd, "clear") == 0) {
		/* Clear
		 */
		if (param == NULL) {
			fprintf(fp, "  clear what?\n");
#ifdef ENABLE_CACHE
		} else if (strcmp(param, "cache") == 0) {
			fprintf(fp, "  %d files removed from the cache.\n", clear_cache());
#endif
		} else if (strcmp(param, "screen") == 0) {
			fprintf(fp, "\033[2J\033[H");
		} else if (strcmp(param, "counters") == 0) {
			clear_counters();
		} else {
			fprintf(fp, "  clear it yourself!\n");
		}
	} else if (strcmp(cmd, "help") == 0) {
		/* Help
		 */
		show_help(fp);
	} else if (strcmp(cmd, "kick") == 0) {
		/* Kick
		 */
		if (param == NULL) {
			fprintf(fp, "  kick what?\n");
		} else if (strcmp(param, "all") == 0) {
			fprintf(fp, "   %d clients have been kicked.\n", disconnect_clients(config));
		} else if ((id = str_to_int(param)) != -1) {
			if (kick_client(id) == 1) {
				fprintf(fp, "  client has been kicked.\n");
			} else {
				fprintf(fp, "  client not found!\n");
			}
		} else if (parse_ip(param, &ip) != -1) {
			fprintf(fp, "  %d clients have been kicked.\n", kick_ip(&ip));
		} else if (strcmp(param, "yourself") == 0) {
			fprintf(fp, "  I can't. I'm a computer.\n");
		} else if (strcmp(param, "me") == 0) {
			fprintf(fp, "  you need help...\n");
		} else {
			fprintf(fp, "  %s kicked back. Ouch!\n", param);
		}
	} else if (strcmp(cmd, "show") == 0) {
		/* Show
		 */
		if (param == NULL) {
			fprintf(fp, "  show what?\n");
		} else if (strcmp(param, "bans") == 0) {
			print_ban_list(fp);
#ifdef ENABLE_CACHE
		} else if (strcmp(param, "cache") == 0) {
			print_cache_list(fp);
#endif
		} else if (strcmp(param, "clients") == 0) {
			print_client_list(fp);
		} else if (strcmp(param, "requests") == 0) {
			admin->show_requests = true;
		} else if (strcmp(param, "status") == 0) {
			show_status(fp);
#ifdef ENABLE_THREAD_POOL
		} else if (strcmp(param, "threads") == 0) {
			show_thread_pool(fp);
#endif
		} else {
			fprintf(fp, "  can't show that!\n");
		}
	} else if (strcmp(cmd, "unban") == 0) {
		/* Unban
		 */
		if (param == NULL) {
			fprintf(fp, "  unban who?\n");
		} else if (strcmp(param, "all") == 0) {
			default_ipv4(&ip);
			count = unban_ip(&ip);
#ifdef ENABLE_IPV6
			default_ipv6(&ip);
			count += unban_ip(&ip);
#endif
			fprintf(fp, "  %d IPs have been unbanned.\n", count);
		} else if (parse_ip(param, &ip) == -1) {
			fprintf(fp, "  invalid IP!\n");
		} else if (unban_ip(&ip) == 1) {
			fprintf(fp, "  IP has been unbanned.\n");
		} else {
			fprintf(fp, "  IP not found!\n");
		}
	} else if ((strcmp(cmd, "quit") == 0) || (strcmp(cmd, "exit") == 0)) {
		/* Quit
		 */
		retval = cc_DISCONNECT;
	} else if (strcmp(cmd, "") != 0) {
		/* Unknown
		 */
		fprintf(fp, "  unknown command!\n");
	}

	return retval;
}

/* Handle a administrator tomahawk.
 */
static int handle_admin(t_admin *admin, t_config *config) {
	int retval = cc_OKE;
	char line[MAX_CMD_SIZE + 1], *pwd, encrypted[33];
	unsigned char digest[16];

	if (fgets(line, MAX_CMD_SIZE, admin->fp) != NULL) {
		line[MAX_CMD_SIZE] = '\0';
		admin->timer = MAX_IDLE_TIME;
		if (strlen(line) >= MAX_CMD_SIZE - 1) {
			do {
				if (fgets(line, MAX_CMD_SIZE, admin->fp) == NULL) {
					return cc_DISCONNECT;
				}
			} while (strlen(line) >= MAX_CMD_SIZE - 1);
			if (admin->authenticated == false) {
				fprintf(admin->fp, "\033[00m");
				retval = cc_DISCONNECT;
			}
			fprintf(admin->fp, "  don't do that!\n");
		} else if (admin->show_requests) {
			admin->show_requests = false;
		} else if (admin->authenticated) {
			retval = run_tomahawk(remove_spaces(line), admin, config);
		} else {
			fprintf(admin->fp, "\033[A\033[K\033[m\n"); /* Move cursor up, clear line and reset color */

			pwd = remove_spaces(line);
			mbedtls_md5((unsigned char*)pwd, strlen(pwd), digest);
			md5_bin2hex(digest, encrypted);
			memset(line, 0, MAX_CMD_SIZE);

			if ((admin->authenticated = (strcmp(encrypted, config->tomahawk_port->binding_id) == 0)) == false) {
				retval = cc_DISCONNECT;
				fprintf(admin->fp, "Password incorrect\n\n");
			} else {
				fprintf(admin->fp, "Welcome. Use 'help' for help. Auto-logout after %d seconds idle-time.\n\n", MAX_IDLE_TIME);
				fflush(admin->fp);
			}
		}
	} else {
		fprintf(admin->fp, "  read error!\n");
		retval = cc_DISCONNECT;
	}

	if ((retval == 0) && (admin->show_requests == false)) {
		fprintf(admin->fp, "%s", prompt);
		fflush(admin->fp);
	}

	return retval;
}

int prepare_admins_for_poll(struct pollfd *current_poll) {
	t_admin *admin;
	int number_of_admins = 0;

	pthread_mutex_lock(&tomahawk_mutex);

	admin = adminlist;
	while (admin != NULL) {
		current_poll->fd = admin->socket;
		current_poll->events = POLL_EVENT_BITS;
		admin->poll_data = current_poll;

		number_of_admins++;
		current_poll++;

		admin = admin->next;
	}

	pthread_mutex_unlock(&tomahawk_mutex);

	return number_of_admins;
}

void handle_admins(t_config *config) {
	t_admin *admin, *prev = NULL, *next;

	pthread_mutex_lock(&tomahawk_mutex);

	admin = adminlist;
	while (admin != NULL) {
		next = admin->next;

		if (admin->poll_data->revents != 0) {
			if (handle_admin(admin, config) == cc_DISCONNECT) {
				if (prev == NULL) {
					adminlist = next;
				} else {
					prev->next = next;
				}

				fclose(admin->fp);
				free(admin);
				admin = prev;
			}
		}

		prev = admin;
		admin = next;
	}

	pthread_mutex_unlock(&tomahawk_mutex);
}

#endif
