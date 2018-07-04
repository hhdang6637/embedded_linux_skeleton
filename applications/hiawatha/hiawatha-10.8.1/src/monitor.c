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

#ifdef ENABLE_MONITOR

#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <zlib.h>
#include "global.h"
#include "monitor.h"
#include "libstr.h"
#include "ip.h"
#include "memdbg.h"

#define MAX_MONITOR_BUFFER_SIZE 50 * KILOBYTE
#define MAX_TIMESTAMP_SIZE      16
#define MAX_FILENAME_SIZE       35
#define FLUSH_INTERVAL          MINUTE

static char *monitor_buffer = NULL;
static int monitor_buffer_size;
static pthread_mutex_t monitor_buffer_mutex;
static int stats_delay;
static char *filename;
static int filename_offset;
static t_config *server_config;

/* Reset server record
 */
static void reset_server_stats(t_monitor_srv_stats *stats) {
	if (stats != NULL) {
		stats->connections = 0;
		stats->result_bad_request = 0;
	}
}

/* Reset record
 */
static void reset_host_stats(t_monitor_host_stats *stats) {
	if (stats != NULL) {
		stats->requests = 0;
		stats->bytes_sent = 0;
		stats->bans = 0;
		stats->exploit_attempts = 0;
		stats->failed_logins = 0;

		stats->result_forbidden = 0;
		stats->result_not_found = 0;
		stats->result_internal_error = 0;
	}
}

static void reset_cgi_stats(t_monitor_host_stats *stats) {
	if (stats != NULL) {
		stats->time_0_1 = 0;
		stats->time_1_3 = 0;
		stats->time_3_10 = 0;
		stats->time_10_x = 0;
		stats->timed_out = 0;
		stats->cgi_errors = 0;
	}
}

/* Write monitor buffer to disk
 */
static int flush_monitor_buffer(void) {
	int handle, bytes_written, total_written;
	gzFile gzhandle;

	if (monitor_buffer_size == 0) {
		return 0;
	}

	snprintf(filename + filename_offset, MAX_FILENAME_SIZE, "%ld.txt.gz", (long)time(NULL));
	if ((handle = open(filename, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP)) == -1) {
		return -1;
	}
	fchmod(handle, S_IRUSR | S_IWUSR);

	if ((gzhandle = gzdopen(handle, "w6")) == NULL) {
		close(handle);
		unlink(filename);
		return -1;
	}

	total_written = 0;
	while (total_written < monitor_buffer_size) {
		if ((bytes_written = gzwrite(gzhandle, monitor_buffer + total_written, monitor_buffer_size - total_written)) == -1) {
			if (gzclose(gzhandle) != Z_OK) {
				close(handle);
			}
			unlink(filename);
			return -1;
		}
		total_written += bytes_written;
	}

	if (gzclose(gzhandle) != Z_OK) {
		close(handle);
	}

	monitor_buffer_size = 0;

	return 0;
}

/* Make enough space in monitor buffer
 */
static bool enough_space_for_entry(size_t event_size) {
	if (event_size > MAX_MONITOR_BUFFER_SIZE) {
		return false;
	}

	if (monitor_buffer_size + event_size > MAX_MONITOR_BUFFER_SIZE) {
		return flush_monitor_buffer() == 0;
	}

	return true;
}

/* Initialize monitor module
 */
int init_monitor_module(t_config *config) {
	t_host *host;

	server_config = config;

	if ((monitor_buffer = (char*)malloc(MAX_MONITOR_BUFFER_SIZE)) == NULL) {
		return -1;
	}
	monitor_buffer_size = 0;

	filename_offset = strlen(config->monitor_directory) + 1;
	if ((filename = (char*)malloc(filename_offset + MAX_FILENAME_SIZE + 1)) == NULL) {
		return -1;
	}
	memcpy(filename, config->monitor_directory, filename_offset);
	filename[filename_offset - 1] = '/';
	filename[filename_offset + MAX_FILENAME_SIZE] = '\0';

	host = config->first_host;
	while (host != NULL) {
		if ((host->monitor_host_stats = (t_monitor_host_stats*)malloc(sizeof(t_monitor_host_stats))) == NULL) {
			return -1;
		}
		reset_host_stats(host->monitor_host_stats);
		reset_cgi_stats(host->monitor_host_stats);

		host = host->next;
	}

	reset_server_stats(&(config->monitor_srv_stats));

	stats_delay = FLUSH_INTERVAL / TASK_RUNNER_INTERVAL;

	if (pthread_mutex_init(&monitor_buffer_mutex, NULL) != 0) {
		return -1;
	}

	return 0;
}

/* Stop monitor module
 */
void shutdown_monitor_module() {
	time_t now;

	now = time(NULL);

	stats_delay = 0;
	monitor_stats_to_buffer(server_config, now);
	flush_monitor_buffer();
}

static int add_string_to_buffer(char *str) {
	size_t size;
	int result = 0;

	if ((monitor_buffer == NULL) || (str == NULL)) {
		return -1;
	}
	size = strlen(str);

	pthread_mutex_lock(&monitor_buffer_mutex);

	if (enough_space_for_entry(size) == false) {
		result = -1;
	} else {
		memcpy(monitor_buffer + monitor_buffer_size, str, size);
		monitor_buffer_size += size;
	}

	pthread_mutex_unlock(&monitor_buffer_mutex);

	return result;
}

/* Monitor event
 */
int monitor_event(char *event, ...) {
	char str[1024];
	int size;
	va_list args;

	size = sprintf(str, "event\t");

	va_start(args, event);
	size += vsnprintf(str + size, 1023 - size, event, args);
	va_end(args);

	if (size >= 1023) {
		return -1;
	}

	if ((size += snprintf(str + size, 1023 - size, "\t%ld\n", (long)time(NULL))) >= 1023) {
		return -1;
	}

	return add_string_to_buffer(str);
}

/* Monitor version
 */
int monitor_version(char *version, char *modules) {
	char str[256];

	if (snprintf(str, 256, "version\t%s%s\n", version, modules) >= 255) {
		return -1;
	}

	return add_string_to_buffer(str);
}

/* Host statistics
 */
int monitor_stats_to_buffer(t_config *config, time_t now) {
	static int timer = 0;
	time_t timestamp_begin, timestamp_end;
	t_host *host;
	char str[256];
	int len;

	if (timer++ < stats_delay) {
		return 0;
	}
	timer = 0;

	timestamp_end = now;
	timestamp_begin = timestamp_end - FLUSH_INTERVAL;

	/* Monitor host stat
	 */
	host = config->first_host;
	while (host != NULL) {
		if (host->monitor_host) {
			host = host->next;
			continue;
		}

		if (host->monitor_host_stats->requests + (long)host->monitor_host_stats->bytes_sent + host->monitor_host_stats->bans +
		    host->monitor_host_stats->exploit_attempts + host->monitor_host_stats->failed_logins +
			host->monitor_host_stats->result_forbidden + host->monitor_host_stats->result_not_found +
			host->monitor_host_stats->result_internal_error > 0) {

			len = snprintf(str, 255, "host\t%ld\t%ld\t%s\t%d\t%ld\t%d\t%d\t%d\t%d\t%d\t%d\n",
				(long)timestamp_begin, (long)timestamp_end, host->hostname.item[0],
				host->monitor_host_stats->requests, (long)host->monitor_host_stats->bytes_sent, host->monitor_host_stats->bans,
				host->monitor_host_stats->exploit_attempts, host->monitor_host_stats->failed_logins,
				host->monitor_host_stats->result_forbidden, host->monitor_host_stats->result_not_found,
				host->monitor_host_stats->result_internal_error);

			if (len < 255) {
				add_string_to_buffer(str);
			}

			reset_host_stats(host->monitor_host_stats);
		}

		if (host->monitor_host_stats->time_0_1 + host->monitor_host_stats->time_1_3 +
		    host->monitor_host_stats->time_3_10 + host->monitor_host_stats->time_10_x +
			host->monitor_host_stats->timed_out + host->monitor_host_stats->cgi_errors > 0) {

			len = snprintf(str, 255, "cgi\t%ld\t%ld\t%s\t%d\t%d\t%d\t%d\t%d\n",
				(long)timestamp_begin, (long)timestamp_end, host->hostname.item[0],
				host->monitor_host_stats->time_0_1, host->monitor_host_stats->time_1_3,
				host->monitor_host_stats->time_3_10, host->monitor_host_stats->time_10_x,
				host->monitor_host_stats->cgi_errors);

			if (len < 255) {
				add_string_to_buffer(str);
			}

			if (host->monitor_host_stats->timed_out > 0) {
				monitor_event( "%d CGI application(s) timed out for %s", host->monitor_host_stats->timed_out, host->hostname.item[0]);
			}

			reset_cgi_stats(host->monitor_host_stats);
		}

		host = host->next;
	}

	/* Monitor server stats
	 */
	if (config->monitor_srv_stats.connections + config->monitor_srv_stats.result_bad_request > 0) {
		len = snprintf(str, 255, "server\t%ld\t%ld\t%d\t%d\n",
			(long)timestamp_begin, (long)timestamp_end,
			config->monitor_srv_stats.connections, config->monitor_srv_stats.result_bad_request);

		if (len < 255) {
			add_string_to_buffer(str);
		}

		reset_server_stats(&(config->monitor_srv_stats));
	}

	flush_monitor_buffer();

	return 0;
}

/* Stats monitor functions
 */
void monitor_count_connection(t_session *session) {
	session->config->monitor_srv_stats.connections++;
}

void monitor_count_bad_request(t_session *session) {
	session->config->monitor_srv_stats.result_bad_request++;
}

void monitor_count_host(t_session *session) {
	if (session->host->monitor_host_stats == NULL) {
		return;
	}

	session->host->monitor_host_stats->bytes_sent += session->bytes_sent;
	session->host->monitor_host_stats->requests++;

	switch (session->return_code) {
		case 403:
			session->host->monitor_host_stats->result_forbidden++;
			break;
		case 404:
			session->host->monitor_host_stats->result_not_found++;
			break;
		case 500:
			session->host->monitor_host_stats->result_internal_error++;
			break;
	}
}

void monitor_count_ban(t_session *session) {
	if (session->host->monitor_host_stats == NULL) {
		return;
	}

	session->host->monitor_host_stats->bans++;
}

void monitor_count_exploit_attempt(t_session *session) {
	if (session->host->monitor_host_stats == NULL) {
		return;
	}

	session->host->monitor_host_stats->exploit_attempts++;
}

void monitor_count_failed_login(t_session *session) {
	if (session->host->monitor_host_stats == NULL) {
		return;
	}

	session->host->monitor_host_stats->failed_logins++;
}

void monitor_count_cgi(t_session *session, int runtime, bool timed_out, bool error) {
	if ((runtime >= 0) && (runtime < 1)) {
		session->host->monitor_host_stats->time_0_1++;
	} else if ((runtime >= 1) && (runtime < 3)) {
		session->host->monitor_host_stats->time_1_3++;
	} else if ((runtime >= 3) && (runtime < 10)) {
		session->host->monitor_host_stats->time_3_10++;
	} else {
		session->host->monitor_host_stats->time_10_x++;
	}

	if (timed_out) {
		session->host->monitor_host_stats->timed_out++;
	}

	if (error) {
		session->host->monitor_host_stats->cgi_errors++;
	}
}

#endif
