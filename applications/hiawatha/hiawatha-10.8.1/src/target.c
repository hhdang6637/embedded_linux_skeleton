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
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "global.h"
#include "alternative.h"
#include "client.h"
#include "libstr.h"
#include "libfs.h"
#include "target.h"
#include "http.h"
#include "httpauth.h"
#include "log.h"
#include "cgi.h"
#include "send.h"
#include "cache.h"
#include "monitor.h"
#include "tomahawk.h"
#include "xslt.h"
#include "memdbg.h"
#include "mbedtls/sha256.h"

#define FILE_BUFFER_SIZE      32 * KILOBYTE
#define MAX_OUTPUT_HEADER     16 * KILOBYTE
#define CGI_BUFFER_SIZE       32 * KILOBYTE
#define RPROXY_BUFFER_SIZE    32 * KILOBYTE
#define MAX_TRACE_HEADER       2 * KILOBYTE
#define WS_BUFFER_SIZE        32 * KILOBYTE
#define VALUE_SIZE            64
#define WAIT_FOR_LOCK          3

#define rs_QUIT       -1
#define rs_DISCONNECT -2
#define rs_FORCE_QUIT -3

#define NEW_FILE -1

char *fb_alterlist = "access denied via alterlist";

extern char *fb_filesystem;
extern char *fb_symlink;
extern char *hs_eol;
extern char *hs_conn;
extern char *hs_concl;
extern char *hs_conlen;
extern char *hs_contyp;
extern char *hs_chunked;

extern char *upgrade_websocket;

/* Read a file from disk and send it to the client.
 */
int send_file(t_session *session) {
	char *buffer = NULL, value[VALUE_SIZE + 1], *pos, *date;
	char *range = NULL, *range_begin, *range_end, gz_file[1024], gz_hex[65];
	bool use_gz_file = false;
	unsigned char gz_hash[32];
	long bytes_read, speed;
	off_t file_size, send_begin, send_end, send_size;
	int  retval, handle = -1;
	struct stat status, gz_status;
	struct tm fdate;
#ifdef ENABLE_CACHE
	char *file_for_cache = NULL;
	t_cached_object *cached_object;
	int result;
#endif

#ifdef ENABLE_DEBUG
	session->current_task = "send file";
#endif
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_FILE);
#endif

	session->mimetype = get_mimetype(session->extension, session->config->mimetype);
	session->send_expires = true;

	if (session->handling_error == false) {
		if ((range = get_http_header("Range:", session->http_headers)) != NULL) {
			goto no_gzip;
		}
	}

	/* GZip content encoding
	 */
	if (file_can_be_compressed(session) == false) {
		goto no_gzip;
	} else if ((pos = get_http_header("Accept-Encoding:", session->http_headers)) == NULL) {
		goto no_gzip;
	} else if (strstr(pos, "gzip") == NULL) {
		goto no_gzip;
	}

	mbedtls_sha256((unsigned char*)session->file_on_disk, strlen(session->file_on_disk), gz_hash, 0);
	sha256_bin2hex(gz_hash, gz_hex);

	if (snprintf(gz_file, 1023, "%s/%s.gz", session->config->gzipped_directory, gz_hex) > 1020) {
		goto no_gzip;
	}

	if (stat(session->file_on_disk, &status) == -1) {
		goto no_gzip;
	} else if (stat(gz_file, &gz_status) == -1) {
		/* GZipped file does not exist
		 */
		if (gzip_file(session->file_on_disk, gz_file) == -1) {
			goto no_gzip;
		}
		if ((handle = open(gz_file, O_RDONLY)) != -1) {
			session->encode_gzip = true;
			use_gz_file = true;
		}
	} else {
		/* GZipped file exists
		 */
		if ((status.st_mtime > gz_status.st_mtime) || (status.st_ctime > gz_status.st_ctime)) {
			unlink(gz_file);
			if (gzip_file(session->file_on_disk, gz_file) == -1) {
				goto no_gzip;
			}
		}
		if ((handle = open(gz_file, O_RDONLY)) != -1) {
			session->encode_gzip = true;
			use_gz_file = true;
		}
	}
no_gzip:

	/* Open the file for reading
	 */
	if (handle == -1) {
		if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
			if (errno == EACCES) {
				log_error_session(session, fb_filesystem);
				return 403;
			}
			return 404;
		}
	}

	if (in_charlist(session->extension, &(session->config->block_extensions))) {
		session->encode_gzip = false;
		close(handle);
		return 403;
	}

#ifdef ENABLE_FILEHASHES
	/* File hashes
	 */
	if ((session->host->file_hashes != NULL) && (session->letsencrypt_auth_request == false)) {
		if (file_hash_match(session->file_on_disk, session->host->file_hashes) == false) {
			log_error_file(session, session->file_on_disk, "invalid file hash");
#ifdef ENABLE_MONITOR
			if (session->config->monitor_enabled) {
				monitor_count_exploit_attempt(session);
				monitor_event("Invalid file hash for %s", session->file_on_disk);
			}
#endif
			close(handle);
			return 403;
		}
	}
#endif

	/* Symlink check
	 */
	if (session->host->follow_symlinks == false) {
		switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
			case fb_error:
				close(handle);
				log_error_session(session, "error while scanning file for symlinks");
				return 500;
			case fb_not_found:
				close(handle);
				return 404;
			case fb_no_access:
			case fb_yes:
				close(handle);
				log_error_session(session, fb_symlink);
				return 403;
			case fb_no:
				break;
		}
	}

	/* Modified-Since
	 */
	if (session->handling_error == false) {
		if ((date = get_http_header("If-Modified-Since:", session->http_headers)) != NULL) {
			if (if_modified_since(session->file_on_disk, date) == 0) {
				close(handle);
				return 304;
			}
		} else if ((date = get_http_header("If-Unmodified-Since:", session->http_headers)) != NULL) {
			if (if_modified_since(session->file_on_disk, date) == 1) {
				close(handle);
				return 412;
			}
		}
	}

	/* Set throttlespeed
	 */
	pos = session->uri + session->uri_len;
	while ((*pos != '.') && (pos != session->uri)) {
		pos--;
	}
	if (*pos == '.') {
		if ((speed = get_throttlespeed(pos, session->config->throttle)) != 0) {
			if ((session->throttle == 0) || (speed < session->throttle)) {
				session->throttle = speed;
			}
		}
		if ((speed = get_throttlespeed(session->mimetype, session->config->throttle)) != 0) {
			if ((session->throttle == 0) || (speed < session->throttle)) {
				session->throttle = speed;
			}
		}
	}

	if (use_gz_file) {
		file_size = filesize(gz_file);
	}  else {
		file_size = filesize(session->file_on_disk);
	}
	if (file_size == -1) {
		close(handle);
		log_error_session(session, "error while determining filesize");
		return 500;
	}

	send_begin = 0;
	send_end = file_size - 1;
	send_size = file_size;

	/* Range
	 */
	if (range != NULL) {
		/* Check for multi-range
		 */
		if (strchr(range, ',') != NULL) {
			close(handle);
			return 416;
		}

		if (strncmp(range, "bytes=", 6) == 0) {
			if ((range = strdup(range + 6)) == NULL) {
				close(handle);
				log_error_session(session, "strdup() error");
				return 500;
			}

			if (split_string(range, &range_begin, &range_end, '-') == 0) {
				if (*range_begin != '\0') {
					if ((send_begin = str_to_int(range_begin)) >= 0) {
						if (*range_end != '\0') {
							if ((send_end = str_to_int(range_end)) >= 0) {
								/* bytes=XX-XX */
								session->return_code = 206;
							}
						} else {
							/* bytes=XX- */
							session->return_code = 206;
						}
					}
				} else {
					if ((send_begin = str_to_int(range_end)) >= 0) {
						/* bytes=-XX */
						send_begin = file_size - send_begin - 1;
						session->return_code = 206;
					}
				}

				if (session->return_code == 206) {
					if (send_begin >= file_size) {
						close(handle);
						free(range);
						return 416;
					}
					if (send_begin < 0) {
						send_begin = 0;
					}
					if (send_end >= file_size) {
						send_end = file_size - 1;
					}
					if (send_begin <= send_end) {
						send_size = send_end - send_begin + 1;
					} else {
						close(handle);
						free(range);
						return 416;
					}
				}

				/* Change filepointer offset
				 */
				if (send_begin > 0) {
					if (lseek(handle, send_begin, SEEK_SET) == -1) {
						session->return_code = 200;
					}
				}

				if (session->return_code == 200) {
					send_begin = 0;
					send_end = file_size - 1;
					send_size = file_size;
				}
			}
			free(range);
		}
	}

	if (session->extension != NULL) {
		if (strcmp(session->extension, "svgz") == 0) {
			session->encode_gzip = true;
		}
	}

	retval = -1;
	if (send_header(session) == -1) {
		goto fail;
	}
	if (session->return_code == 401) {
		if (session->host->auth_method == basic) {
			if (send_basic_auth(session) == -1) {
				goto fail;
			}
		} else {
			if (send_digest_auth(session) == -1) {
				goto fail;
			}
		}
	}

	value[VALUE_SIZE] = '\0';

	/* Last-Modified
	 */
	if (stat(session->file_on_disk, &status) == -1) {
		goto fail;
	} else if (gmtime_r(&(status.st_mtime), &fdate) == NULL) {
		goto fail;
	} else if (send_buffer(session, "Last-Modified: ", 15) == -1) {
		goto fail;
	} else if (strftime(value, VALUE_SIZE, "%a, %d %b %Y %X GMT\r\n", &fdate) == 0) {
		goto fail;
	} else if (send_buffer(session, value, strlen(value)) == -1) {
		goto fail;
	}

	/* Content-Range
	 */
	if (session->return_code == 206) {
		if (send_buffer(session, "Content-Range: bytes ", 21) == -1) {
			goto fail;
		} else if (snprintf(value, VALUE_SIZE, "%lld-%lld/%lld\r\n", (long long)send_begin, (long long)send_end, (long long)file_size) == -1) {
			goto fail;
		} else if (send_buffer(session, value, strlen(value)) == -1) {
			goto fail;
		}
	}

	if (send_buffer(session, hs_conlen, 16) == -1) {
		goto fail;
	} else if (snprintf(value, VALUE_SIZE, "%lld\r\n\r\n", (long long)send_size) == -1) {
		goto fail;
	} else if (send_buffer(session, value, strlen(value)) == -1) {
		goto fail;
	}
	session->header_sent = true;

	if ((session->request_method != HEAD) && (send_size > 0)) {
#ifdef ENABLE_CACHE
#ifdef ENABLE_MONITOR
		if (session->host->monitor_host) {
			cached_object = NULL;
		} else
#endif
		{
			file_for_cache = use_gz_file ? gz_file : session->file_on_disk;
			if ((cached_object = search_cache_for_file(session, file_for_cache)) == NULL) {
				cached_object = add_file_to_cache(session, file_for_cache);
			}
		}

		if (cached_object != NULL) {
			if (send_begin + send_size > cached_object->content_length) {
				done_with_cached_object(cached_object, true);
				cached_object = NULL;
			}
		}

		if (cached_object != NULL) {
			result = send_buffer(session, cached_object->content + send_begin, send_size);
			done_with_cached_object(cached_object, false);
			cached_object = NULL;

			if (result == -1) {
				goto fail;
			}
		} else
#endif
		if ((buffer = (char*)malloc(FILE_BUFFER_SIZE)) == NULL) {
			goto fail;
		} else {
			do {
				switch ((bytes_read = read(handle, buffer, FILE_BUFFER_SIZE))) {
					case -1:
						if (errno != EINTR) {
							goto fail;
						}
						break;
					case 0:
						send_size = 0;
						break;
					default:
						if (bytes_read > send_size) {
							bytes_read = send_size;
						}
						if (send_buffer(session, buffer, bytes_read) == -1) {
							goto fail;
						}
						send_size -= bytes_read;
				}
			} while (send_size > 0);

			memset(buffer, 0, FILE_BUFFER_SIZE);
		}
	}

	retval = 200;

fail:
	if (buffer != NULL) {
		free(buffer);
	}

	close(handle);

	return retval;
}

static int extract_http_code(char *data) {
	int result = -1;
	char *code, c;

	while (*data == ' ') {
		data++;
	}
	code = data;

	while (*data != '\0') {
		if ((*data == '\r') || (*data == ' ')) {
			c = *data;
			*data = '\0';
			result = str_to_int(code);
			*data = c;
			break;
		}
		data++;
	}

	return result;
}

static int remove_header(char *buffer, char *header, int *header_length, unsigned long *size) {
	char *pos;
	size_t len;

	if ((pos = find_cgi_header(buffer, *header_length, header)) == NULL) {
		return 0;
	}

	len = strlen(header);
	while (*(pos + len) != '\n') {
		if (*(pos + len) == '\0') {
			return 0;
		}
		len++;
	}
	len++;

	memmove(pos, pos + len, *size - len - (pos - buffer));

	*header_length -= len;
	*size -= len;

	return len;
}

/* Run a CGI program and send output to the client.
 */
int execute_cgi(t_session *session) {
	int retval = 200, result, handle, len, header_length, value, flush_after_send = false, delta, return_code;
	char *end_of_header, *str_begin, *str_end, *code, c, *str, *sendfile = NULL;
	bool in_body = false, send_in_chunks = true, wrap_cgi, check_file_exists;
	t_cgi_result cgi_result;
	t_connect_to *connect_to;
	t_cgi_info cgi_info;
	pid_t cgi_pid = -1;
#ifdef CYGWIN
	char *old_path, *win32_path;
#endif
#ifdef ENABLE_CACHE
	bool skip_cache;
	t_cached_object *cached_object;
	char *cache_buffer = NULL, *cookie;
	int  cache_size = 0, cache_time = 0, i;
#endif
#ifdef ENABLE_MONITOR
	bool timed_out = false, measure_runtime = false;
	bool error_printed = false;
	struct timeval tv_begin, tv_end;
	struct timezone tz_begin, tz_end;
	int runtime, diff;
	char *event_key, *event_value, *event_end;
#endif

#ifdef ENABLE_DEBUG
	session->current_task = "execute CGI";
#endif
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_CGI);
#endif

	if (session->cgi_type != fastcgi) {
		wrap_cgi = (session->host->wrap_cgi != NULL) ||
			((session->local_user != NULL) && session->config->wrap_user_cgi);
	} else {
		wrap_cgi = false;
	}

	/* HTTP/1.0 does not support chunked Transfer-Encoding.
	 */
	if (*(session->http_version + 7) == '0') {
		session->keep_alive = false;
	}

	if ((wrap_cgi == false) && (session->cgi_type != fastcgi)) {
		check_file_exists = true;
	} else if ((session->cgi_type == fastcgi) && (session->fcgi_server != NULL)) {
		check_file_exists = false;
	} else {
		check_file_exists = false;
	}

	if (check_file_exists) {
		if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
			if (errno == EACCES) {
				log_error_session(session, fb_filesystem);
				return 403;
			}
			return 404;
		} else {
			close(handle);
		}

#ifdef ENABLE_FILEHASHES
		/* File hashes
		 */
		if (session->host->file_hashes != NULL) {
			if (file_hash_match(session->file_on_disk, session->host->file_hashes) == false) {
				log_error_file(session, session->file_on_disk, "invalid file hash");
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_count_exploit_attempt(session);
					monitor_event("Invalid file hash for %s", session->file_on_disk);
				}
#endif
				return 403;
			}
		}
#endif
	}

	if (session->host->execute_cgi == false) {
		log_error_session(session, "CGI execution not allowed");
		return 403;
	}

#ifdef CYGWIN
	if ((session->config->platform == windows) && (session->cgi_type == binary)) {
		chmod(session->file_on_disk, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	}
#endif

	if ((wrap_cgi == false) && (session->cgi_type != fastcgi)) {
		if (session->cgi_type == binary) {
			switch (can_execute(session->file_on_disk, session->config->server_uid, session->config->server_gid, &(session->config->groups))) {
				case fb_error:
					log_error_session(session, "error during CGI preprocess");
					return 500;
				case fb_not_found:
					return 404;
				case fb_no_access:
				case fb_no:
					log_error_session(session, fb_filesystem);
					return 403;
				case fb_yes:
					break;
			}
		}

		if (session->host->follow_symlinks == false) {
			switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
				case fb_error:
					log_error_session(session, "error while searching for symlinks in CGI path");
					return 500;
				case fb_not_found:
					return 404;
				case fb_no_access:
				case fb_yes:
					log_error_session(session, fb_symlink);
					return 403;
				case fb_no:
					break;
			}
		}
	}

	/* Prevent SQL injection
	 */
	if (session->host->prevent_sqli != p_no) {
		result = prevent_sqli(session);
		if ((result > 0) && (session->host->prevent_sqli >= p_prevent)) {
			session->error_cause = ec_SQL_INJECTION;
			return -1;
		} else if (result == -1) {
			return -1;
		}
	}

	/* Prevent Cross-site Scripting
	 */
	if (session->host->prevent_xss != p_no) {
		if ((prevent_xss(session) > 0) && (session->host->prevent_xss == p_block)) {
			session->error_cause = ec_XSS;
			return -1;
		}
	}

	/* Prevent Cross-site Request Forgery
	 */
	if (session->host->prevent_csrf != p_no) {
		if ((prevent_csrf(session) > 0) && (session->host->prevent_csrf == p_block)) {
			session->error_cause = ec_CSRF;
			return -1;
		}
	}

#ifdef ENABLE_CACHE
	/* Search for CGI output in cache
	 */
	skip_cache = false;
	if (session->cookies != NULL) {
		for (i = 0; i < session->host->skip_cache_cookies.size; i++) {
			cookie = session->host->skip_cache_cookies.item[i];
			if ((str = strstr(session->cookies, cookie)) != NULL) {
				if (*(str + strlen(cookie)) != '=') {
					continue;
				}
				if (str > session->cookies) {
					if (*(str - 1) != ' ') {
						continue;
					}
				}
				skip_cache = true;
				break;
			}
		}
	}

	if ((session->request_method == GET) && (skip_cache == false)) {
		if ((cached_object = search_cache_for_cgi_output(session)) != NULL) {
			if (send_header(session) == -1) {
				retval = rs_DISCONNECT;
			} else if (send_buffer(session, cached_object->header, cached_object->header_length) == -1) {
				retval = rs_DISCONNECT;
			} else if (send_buffer(session, cached_object->content, cached_object->content_length) == -1) {
				retval = rs_DISCONNECT;
			}

			done_with_cached_object(cached_object, false);

			return retval;
		}
	}
#endif

	cgi_info.type = session->cgi_type;
	cgi_info.input_buffer_size = cgi_info.error_buffer_size = CGI_BUFFER_SIZE;
	cgi_info.input_len = cgi_info.error_len = 0;

#ifdef CYGWIN
	if ((session->config->platform == windows) && ((session->cgi_type == fastcgi) || (session->cgi_type == script))) {
		if ((old_path = strdup(session->file_on_disk)) == NULL) {
			return -1;
		}
		if ((win32_path = strdup(cygwin_to_windows(old_path))) == NULL) {
			free(old_path);
			return -1;
		}
		free(session->file_on_disk);
		session->file_on_disk = win32_path;
		free(old_path);
	}
#endif

#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled) {
		measure_runtime = gettimeofday(&tv_begin, &tz_begin) == 0;
	}
#endif

	if (session->cgi_type == fastcgi) {
		cgi_info.read_header = true;
		if ((connect_to = select_connect_to(session->fcgi_server, &(session->ip_address))) == NULL) {
			return 503;
		} else if ((cgi_info.from_cgi = connect_to_fcgi_server(connect_to)) == -1) {
			connect_to->available = false;
			log_system(session->config, "can't connect to FastCGI server %s", session->fcgi_server->fcgi_id);
			return 503;
		} else {
			connect_to->available = true;
			if (send_fcgi_request(session, cgi_info.from_cgi) == -1) {
				log_error_session(session, "error while sending data to FastCGI server");
				return 500;
			}
		}
	} else {
		cgi_info.wrap_cgi = wrap_cgi;
		if ((cgi_pid = fork_cgi_process(session, &cgi_info)) == -1) {
			log_error_session(session, "error while forking CGI process");
			return 500;
		}
	}

	if ((cgi_info.input_buffer = (char*)malloc(cgi_info.input_buffer_size + 1)) == NULL) {
		retval = -1;
	} else if ((cgi_info.error_buffer = (char*)malloc(cgi_info.error_buffer_size + 1)) == NULL) {
		free(cgi_info.input_buffer);
		retval = -1;
	}

	if (retval != 200) {
		if (session->cgi_type == fastcgi) {
			close(cgi_info.from_cgi);
		} else {
			close(cgi_info.to_cgi);
			close(cgi_info.from_cgi);
			close(cgi_info.cgi_error);
		}
		return retval;
	}

	cgi_info.deadline = session->time + session->host->time_for_cgi;

	do {
		if (time(NULL) > cgi_info.deadline) {
			cgi_result = cgi_TIMEOUT;
		} else if (session->cgi_type == fastcgi) {
			cgi_result = read_from_fcgi_server(session, &cgi_info);
		} else {
			cgi_result = read_from_cgi_process(session, &cgi_info);
		}

		switch (cgi_result) {
			case cgi_ERROR:
				log_error_session(session, "error while executing CGI");
				retval = 500;
				break;
			case cgi_TIMEOUT:
				log_error_session(session, "CGI application timeout");
				if (in_body) {
					retval = rs_DISCONNECT;
				} else {
					retval = 500;
				}
				if (session->config->kill_timedout_cgi && (session->cgi_type != fastcgi)) {
					if (kill(cgi_pid, SIGTERM) != -1) {
						sleep(1);
						kill(cgi_pid, SIGKILL);
					}
				}
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					timed_out = true;
				}
#endif
				break;
			case cgi_FORCE_QUIT:
				retval = rs_FORCE_QUIT;
				break;
			case cgi_OKE:
				if (cgi_info.error_len > 0) {
					/* Error received from CGI
					 */
					*(cgi_info.error_buffer + cgi_info.error_len) = '\0';
					log_error_cgi(session, cgi_info.error_buffer);
					cgi_info.error_len = 0;
#ifdef ENABLE_MONITOR
					error_printed = true;
#endif
				}

				if (cgi_info.input_len > 0) {
					/* Data received from CGI
					 */
					if (in_body) {
						/* Read content
						 */
						if (session->request_method != HEAD) {
							if (send_in_chunks) {
								result = send_chunk(session, cgi_info.input_buffer, cgi_info.input_len);
							} else {
								result = send_buffer(session, cgi_info.input_buffer, cgi_info.input_len);
							}

							if (result == -1) {
								retval = rs_DISCONNECT;
							} else if (flush_after_send) {
								if (send_in_chunks) {
									result = send_chunk(session, NULL, -1);
								} else {
									result = send_buffer(session, NULL, 0);
								}
							}
						}

#ifdef ENABLE_CACHE
						/* Add body content to cache buffer
						 */
						if ((cache_buffer != NULL) && (retval == 200)) {
							if ((off_t)(cache_size + cgi_info.input_len) > session->config->cache_max_filesize) {
								free(cache_buffer);
								cache_buffer = NULL;
							} else {
								memcpy(cache_buffer + cache_size, cgi_info.input_buffer, cgi_info.input_len);
								cache_size += cgi_info.input_len;
								*(cache_buffer + cache_size) = '\0';
							}
						}
#endif
						cgi_info.input_len = 0;
					} else {
						/* Read CGI header
						 */
						*(cgi_info.input_buffer + cgi_info.input_len) = '\0';

						if ((end_of_header = strstr(cgi_info.input_buffer, "\r\n\r\n")) == NULL) {
							/* Fix crappy CGI headers
							 */
							if ((result = fix_crappy_cgi_headers(&cgi_info)) == -1) {
								log_error_session(session, "error fixing crappy CGI headers");
								retval = 500;
								break;
							} else if (result == 0) {
								end_of_header = strstr(cgi_info.input_buffer, "\r\n\r\n");
							}
						}

						if (end_of_header != NULL) {
							return_code = 200;

							if ((strncmp(cgi_info.input_buffer, "HTTP/1.0 ", 9) == 0) || (strncmp(cgi_info.input_buffer, "HTTP/1.1 ", 9) == 0)) {
								if ((str_end = strstr(cgi_info.input_buffer, "\r\n")) != NULL) {
									return_code = extract_http_code(cgi_info.input_buffer + 9);

									delta = str_end - cgi_info.input_buffer + 2;
									memmove(cgi_info.input_buffer, cgi_info.input_buffer + delta, cgi_info.input_len - delta);
									cgi_info.input_len -= delta;
									end_of_header -= delta;
								}
							}

							header_length = end_of_header + 4 - cgi_info.input_buffer;

							if (return_code == 200) {
								if ((code = find_cgi_header(cgi_info.input_buffer, header_length, "Status:")) != NULL) {
									return_code = extract_http_code(code + 7);
								}
							}

							if ((return_code <= 0) || (return_code > 999)) {
								log_error_session(session, "invalid status code received from CGI");
							} else if (return_code != 200) {
								session->return_code = return_code;

								if (return_code == 500) {
									log_error_session(session, "CGI returned 500 Internal Error");
								}
								if (session->host->trigger_on_cgi_status) {
									retval = return_code;
									break;
								}
							}

							if (session->throttle == 0) {
								if ((str_begin = find_cgi_header(cgi_info.input_buffer, header_length, hs_contyp)) != NULL) {
									if ((str_end = strchr(str_begin, '\r')) != NULL) {
										str_begin += 14;
										c = *str_end;
										*str_end = '\0';
										session->throttle = get_throttlespeed(str_begin, session->config->throttle);
										*str_end = c;
									}
								}
							}

							if ((str = find_cgi_header(cgi_info.input_buffer, header_length, hs_conn)) != NULL) {
								if (strncmp(str + 12, hs_concl, 7) == 0) {
									session->keep_alive = false;
								}

							}

							/* Search for X-Hiawatha-Ban
							 */
							if (session->host->ban_by_cgi) {
								if (ip_allowed(&(session->ip_address), session->config->banlist_mask) != deny) {
									if ((str_begin = find_cgi_header(cgi_info.input_buffer, header_length, "X-Hiawatha-Ban:")) != NULL) {
										str_begin += 15;
										while (*str_begin == ' ') {
											str_begin++;
										}

										str_end = str_begin;
										while ((*str_end != '\r') && (*str_end != '\0')) {
											str_end++;
										}

										if (*str_end == '\r') {
											*str_end = '\0';
											value = str_to_int(str_begin);
											*str_end = '\r';

											if (value > 0) {
												if ((session->host->ban_by_cgi_max > -1) && (value > session->host->ban_by_cgi_max)) {
													value = session->host->ban_by_cgi_max;
												}

												ban_ip(&(session->ip_address), value, session->config->kick_on_ban);
												log_system_session(session, "Client banned for %d seconds by CGI %s", value, session->file_on_disk);
#ifdef ENABLE_MONITOR
												if (session->config->monitor_enabled) {
													monitor_count_ban(session);
												}
#endif
											}
										}
									}
								}
							}

#ifdef ENABLE_MONITOR
							/* Log X-Hiawatha-Monitor header
							 */
							str = cgi_info.input_buffer;
							len = header_length;
							while ((event_key = find_cgi_header(str, len, "X-Hiawatha-Monitor:")) != NULL) {
								event_value = event_key + 19;
								while (*event_value == ' ') {
									event_value++;
								}

								if ((event_end = strstr(event_value, "\r\n")) == NULL) {
									break;
								}

								if (session->config->monitor_enabled) {
									*event_end = '\0';
									if (strcmp(event_value, "exploit_attempt") == 0) {
										monitor_count_exploit_attempt(session);
										log_exploit_attempt(session, "reported by CGI", NULL);
									} else if (strcmp(event_value, "failed_login") == 0) {
										monitor_count_failed_login(session);
										log_error_file(session, session->request_uri, "failed login");
									} else {
										monitor_event("%s", event_value);
									}
									*event_end = '\r';
								}

								event_end += 2;
								memmove(event_key, event_end, cgi_info.input_len - (event_end - cgi_info.input_buffer));

								diff = event_end - event_key;
								header_length -= diff;
								end_of_header -= diff;
								cgi_info.input_len -= diff;

								len = header_length - (str - cgi_info.input_buffer);
							}
#endif

							/* Look for X-Sendfile header
							 */
							if ((sendfile = find_cgi_header(cgi_info.input_buffer, header_length, "X-Sendfile:")) != NULL) {
								sendfile = sendfile + 11;
								while (*sendfile == ' ') {
									sendfile++;
								}

								if ((str = strstr(sendfile, "\r\n")) != NULL) {
									*str = '\0';
									sendfile = strdup(sendfile);
									*str = '\r';
								}

								retval = rs_QUIT;
								break;
							}

#ifdef ENABLE_CACHE
							/* Look for store-in-cache CGI header
							 */
							if ((session->request_method == GET) && (skip_cache == false)) {
								if ((cache_time = cgi_cache_time(cgi_info.input_buffer, header_length)) > 0) {
									if ((cache_buffer = (char*)malloc(session->config->cache_max_filesize + 1)) != NULL) {
										*(cache_buffer + session->config->cache_max_filesize) = '\0';
									}
								}
							}

							/* Look for remove-from-cache CGI header
							 */
							handle_remove_header_for_cgi_cache(session, cgi_info.input_buffer, header_length);
#endif

							/* Look for X-Accel-Buffering header
							 */
							if ((str = find_cgi_header(cgi_info.input_buffer, header_length, "X-Accel-Buffering:")) != NULL) {
								str += 18;
								while (*str == ' ') {
									str++;
								}

								if (strncasecmp(str, "no\r\n", 4) == 0) {
									flush_after_send = true;
								}
							}

							if (find_cgi_header(cgi_info.input_buffer, header_length, "Date:") != NULL) {
								session->send_date = false;
							}

							if (find_cgi_header(cgi_info.input_buffer, header_length, "Location:") != NULL) {
								if (session->return_code == 200) {
									session->return_code = 302;
								}
							}

							/* Remove headers from CGI output
							 */
							while ((delta = remove_header(cgi_info.input_buffer, "X-Hiawatha-", &header_length, &(cgi_info.input_len))) > 0) {
								end_of_header -= delta;
							}
							if ((delta = remove_header(cgi_info.input_buffer, "X-Sendfile:", &header_length, &(cgi_info.input_len))) > 0) {
								end_of_header -= delta;
							}
							if ((delta = remove_header(cgi_info.input_buffer, "Status:", &header_length, &(cgi_info.input_len))) > 0) {
								end_of_header -= delta;
							}

							if (send_header(session) == -1) {
								retval = rs_DISCONNECT;
								break;
							}

							if ((find_cgi_header(cgi_info.input_buffer, header_length, hs_conlen) != NULL) || (session->keep_alive == false)) {
								send_in_chunks = false;
							} else if (send_buffer(session, hs_chunked, 28) == -1) {
								retval = rs_DISCONNECT;
								break;
							}

							/* Send the header.
							 */
							end_of_header += 4;
							len = end_of_header - cgi_info.input_buffer;
							if (send_buffer(session, cgi_info.input_buffer, len) == -1) {
								retval = rs_DISCONNECT;
								break;
							}
							if (send_buffer(session, NULL, 0) == -1) {
								retval = rs_DISCONNECT;
								break;
							}
							session->header_sent = true;

							/* Send first part of the body
							 */
							if (session->request_method != HEAD) {
								if ((len = cgi_info.input_len - len) > 0) {
									if (send_in_chunks) {
										result = send_chunk(session, end_of_header, len);
									} else {
										result = send_buffer(session, end_of_header, len);
									}
									if (result == -1) {
										retval = rs_DISCONNECT;
										break;
									}
								}
							}

#ifdef ENABLE_CACHE
							/* Add header to cache buffer
							 */
							if (cache_buffer != NULL) {
								if ((off_t)(cache_size + cgi_info.input_len) > session->config->cache_max_filesize) {
									clear_free(cache_buffer, cache_size);
									cache_buffer = NULL;
								} else {
									memcpy(cache_buffer + cache_size, cgi_info.input_buffer, cgi_info.input_len);
									cache_size += cgi_info.input_len;
									*(cache_buffer + cache_size) = '\0';
								}
							}
#endif

							in_body = true;
							cgi_info.input_len = 0;
						} else if (cgi_info.input_len > MAX_OUTPUT_HEADER) {
							log_error_session(session, "CGI header too large");
							retval = 500;
							break;
						}
					}
				}
				break;
			case cgi_END_OF_DATA:
				if (in_body) {
					retval = rs_QUIT;
					if (send_in_chunks && (session->request_method != HEAD)) {
						if (send_chunk(session, NULL, 0) == -1) {
							retval = rs_DISCONNECT;
						}
					}
				} else {
					retval = 500;
					if (cgi_info.input_len == 0) {
						log_error_session(session, "no output");
					} else {
						log_error_session(session, "CGI only printed a header, no content");
					}
				}
		} /* switch */
	} while (retval == 200);

#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled && measure_runtime) {
		if (gettimeofday(&tv_end, &tz_end) == 0) {
			runtime = tv_end.tv_sec - tv_begin.tv_sec;
			if (tv_end.tv_usec < tv_begin.tv_usec) {
				runtime--;
			}
			monitor_count_cgi(session, runtime, timed_out, error_printed);
		}
	}
#endif

	session->time = time(NULL);

#ifdef ENABLE_CACHE
	/* Add cache buffer to cache
	 */
	if (cache_buffer != NULL) {
		if (retval == rs_QUIT) {
			add_cgi_output_to_cache(session, cache_buffer, cache_size, cache_time);
		}
		clear_free(cache_buffer, cache_size);
	}
#endif

	if (session->cgi_type == fastcgi) {
		close(cgi_info.from_cgi);
	} else {
		close(cgi_info.to_cgi);
		if (cgi_info.from_cgi != -1) {
			close(cgi_info.from_cgi);
		}
		if (cgi_info.cgi_error != -1) {
			close(cgi_info.cgi_error);
		}
	}

	if (session->config->wait_for_cgi && (cgi_pid != -1)) {
		waitpid(cgi_pid, NULL, 0);
	}

	switch (retval) {
		case rs_DISCONNECT:
		case rs_FORCE_QUIT:
			session->keep_alive = false;
		case rs_QUIT:
			retval = 200;
	}

	clear_free(cgi_info.input_buffer, cgi_info.input_len);
	clear_free(cgi_info.error_buffer, cgi_info.error_len);

	if (sendfile != NULL) {
		str = session->file_on_disk;
		session->file_on_disk = sendfile;

		if (get_target_extension(session) != -1) {
			retval = send_file(session);
		}

		session->file_on_disk = str;

		free(sendfile);
	}

	return retval;
}

/* Handle TRACE requests
 */
int handle_trace_request(t_session *session) {
	int code, body_size;
	size_t len;
	char buffer[MAX_TRACE_HEADER + 1];
	t_http_header *header;

#ifdef ENABLE_DEBUG
	session->current_task = "handle TRACE";
#endif

	body_size = 3;
	body_size += strlen(session->method) + session->uri_len;
	if (session->vars != NULL) {
		body_size += 1 + strlen(session->vars);
	}
	body_size += strlen(session->http_version);

	header = session->http_headers;
	while (header != NULL) {
		body_size += header->length + 1;
		header = header->next;
	}

	buffer[MAX_TRACE_HEADER] = '\0';

	/* Header
	 */
	if (snprintf(buffer, MAX_TRACE_HEADER, "%d\r\nContent-Type: message/http\r\n\r\n", body_size) < 0) {
		log_error_session(session, "snprintf() error");
		return 500;
	} else if (send_header(session) == -1) {
		return -1;
	} else if (send_buffer(session, hs_conlen, 16) == -1) {
		return -1;
	} else if (send_buffer(session, buffer, strlen(buffer)) == -1) {
		return -1;
	}
	session->header_sent = true;

	/* Body
	 */
	if ((code = snprintf(buffer, MAX_TRACE_HEADER, "%s %s", session->method, session->uri)) < 0) {
		return -1;
	} else if (code >= MAX_TRACE_HEADER) {
		return -1;
	} else if (session->vars != NULL) {
		len = strlen(buffer);
		if ((code = snprintf(buffer + len, MAX_TRACE_HEADER - len, "?%s", session->vars)) < 0) {
			return -1;
		} else if (code >= MAX_TRACE_HEADER) {
			return -1;
		}
	}
	len = strlen(buffer);
	if ((code = snprintf(buffer + len, MAX_TRACE_HEADER - len, " %s\r\n", session->http_version)) < 0) {
		return -1;
	} else if (send_buffer(session, buffer, strlen(buffer)) == -1) {
		return -1;
	}

	header = session->http_headers;
	while (header != NULL) {
		if (send_buffer(session, header->data, header->length) == -1) {
			return -1;
		} else if (send_buffer(session, "\n", 1) == -1) {
			return -1;
		}
		header = header->next;
	}

	return 200;
}

/* Determine allowance of alter requests
 */
static t_access allow_alter(t_session *session) {
	t_ip_addr forwarded_ip;
	t_access access;

	if ((access = ip_allowed(&(session->ip_address), session->host->alter_list)) != allow) {
		return access;
	} else if (last_forwarded_ip(session->http_headers, &forwarded_ip) == -1) {
		return allow;
	} else if (ip_allowed(&forwarded_ip, session->host->alter_list) == deny) {
		return deny;
	}

	return unspecified;
}

/* Handle PUT requests
 */
int handle_put_request(t_session *session) {
	int auth_result, handle_write, handle_read = -1, result = -1, total_written = 0, lock_timeout;
	off_t write_begin, write_end, total_size, file_size;
	ssize_t bytes_read;
	char *range, *value, *rest, *buffer;
	bool range_found;
	struct flock file_lock;

#ifdef ENABLE_DEBUG
	session->current_task = "handle PUT";
#endif

	if (session->uploaded_file == NULL) {
		log_error_session(session, "no uploaded file available for PUT request");
		return 500;
	}

	/* Access check
	 */
	switch (allow_alter(session)) {
		case deny:
		case unspecified:
			log_error_session(session, fb_alterlist);
			return 403;
		case allow:
			break;
		case pwd:
			if ((auth_result = http_authentication_result(session, false)) != 200) {
				return auth_result;
			}
			if (group_oke(session, session->remote_user, &(session->host->alter_group)) == false) {
				return 403;
			}
			break;
	}

	if (session->uri_is_dir) {
		return 405;
	}

	range = get_http_header("Content-Range:", session->http_headers);
	range_found = (range != NULL);

	/* Open file for writing
	 */
	if ((handle_write = open(session->file_on_disk, O_WRONLY)) == -1) {
		/* New file */
		if (range_found) {
			return 416;
		}
		if ((handle_write = open(session->file_on_disk, O_CREAT|O_WRONLY, session->host->alter_fmode)) == -1) {
			log_error_session(session, fb_filesystem);
			return 403;
		}
		file_size = NEW_FILE;
		result = 201;
	} else {
		/* Existing file */
		if ((file_size = filesize(session->file_on_disk)) == -1) {
			close(handle_write);
			log_error_session(session, "filesize() error");
			return 500;
		}
		result = 204;
	}

	/* Lock file for writing
	 */
	file_lock.l_type = F_WRLCK;
	file_lock.l_whence = SEEK_SET;
	file_lock.l_start = 0;
	file_lock.l_len = 0;
	file_lock.l_pid = 0;
	lock_timeout = WAIT_FOR_LOCK;

	while (fcntl(handle_write, F_SETLK, &file_lock) == -1) {
		if (errno == EINTR) {
			continue;
		} else if ((lock_timeout > 0) && ((errno == EACCES) || (errno == EAGAIN))) {
			lock_timeout--;
			sleep(1);
		} else {
			log_error_session(session, "can't lock file for writing (PUT)");
			close(handle_write);
			if (file_size == NEW_FILE) {
				unlink(session->file_on_disk);
			}
			return 500;
		}
	}

	file_lock.l_type = F_UNLCK;

	/* Handle upload range
	 */
	if (range_found) {
		if (strncmp(range, "bytes ", 6) != 0) {
			result = 416;
		} else {
			if ((range = strdup(range + 6)) == NULL) {
				result = -1;
			} else if (split_string(range, &value, &rest, '-') == -1) {
				result = 416;
			} else if (strlen(value) > 9) {
				result = 416;
			} else if ((write_begin = str_to_int(value)) == -1) {
				result = 416;
			} else if (split_string(rest, &value, &rest, '/') == -1) {
				result = 416;
			} else if ((write_end = str_to_int(value)) == -1) {
				result = 416;
			} else if ((total_size = str_to_int(rest)) == -1) {
				result = 416;
			} else if (total_size != file_size) {
				result = 416;
			} else if (write_begin > write_end) {
				result = 416;
			} else if (write_begin > file_size) {
				result = 416;
			} else if (session->content_length != (write_end - write_begin + 1)) {
				result = 416;
			} else if (write_begin > 0) {
				if (lseek(handle_write, write_begin, SEEK_SET) == -1) {
					log_error_session(session, "lseek() error");
					result = 500;
				}
			}

			free(range);
		}
	}

	/* Open temporary file for reading
	 */
	if ((result == 201) || (result == 204)) {
		if ((handle_read = open(session->uploaded_file, O_RDONLY)) == -1) {
			fcntl(handle_write, F_SETLK, &file_lock);
			close(handle_write);
			if (file_size == NEW_FILE) {
				unlink(session->file_on_disk);
			}
			log_error_session(session, "can't open uploaded file of PUT request");
			return 500;
		}

		if ((file_size != NEW_FILE) && (range_found == false)) {
			if (ftruncate(handle_write, session->content_length) == -1) {
				log_error_session(session, "ftruncate() error");
				result = 500;
			}
		}

		/* Write content
		 */
		if (result != 500) {
			if ((buffer = (char*)malloc(FILE_BUFFER_SIZE)) != NULL) {
				while (total_written < session->content_length) {
					if ((bytes_read = read(handle_read, buffer, FILE_BUFFER_SIZE)) != -1) {
						if (bytes_read == 0) {
							break;
						} else if (write_buffer(handle_write, buffer, bytes_read) != -1) {
							total_written += bytes_read;
						} else {
							log_error_session(session, "error writing file of PUT request");
							result = 500;
							break;
						}
					} else if (errno != EINTR) {
						log_error_session(session, "error reading file of PUT request");
						result = 500;
						break;
					}
				}
				free(buffer);
			} else {
				log_error_session(session, "malloc() error for PUT request");
				result = 500;
			}
		}
	}

	/* Finish upload
	 */
	if (handle_read != -1) {
		close(handle_read);
	}
	fcntl(handle_write, F_SETLK, &file_lock);
	fsync(handle_write);
	close(handle_write);
	if ((result != 201) && (result != 204) && (file_size == NEW_FILE)) {
		unlink(session->file_on_disk);
	}

	return result;
}

/* Handle DELETE requests
 */
int handle_delete_request(t_session *session) {
	int auth_result;

#ifdef ENABLE_DEBUG
	session->current_task = "handle DELETE";
#endif

	/* Access check
	 */
	switch (allow_alter(session)) {
		case deny:
		case unspecified:
			log_error_session(session, fb_alterlist);
			return 403;
		case allow:
			break;
		case pwd:
			if ((auth_result = http_authentication_result(session, false)) != 200) {
				return auth_result;
			}
			if (group_oke(session, session->remote_user, &(session->host->alter_group)) == false) {
				return 403;
			}
			break;
	}

	/* Don't delete directories
	 */
	if (session->uri_is_dir) {
		return 405;
	}

	/* Delete file
	 */
	if (unlink(session->file_on_disk) == -1) {
		switch (errno) {
			case EACCES:
				log_error_session(session, fb_filesystem);
				return 403;
			case ENOENT:
				return 404;
			case EISDIR:
			case ENOTDIR:
				return 405;
			default:
				log_error_session(session, "error deleting file for DELETE request");
				return 500;
		}
	}

	return 204;
}

#ifdef ENABLE_XSLT
int handle_xml_file(t_session *session, char *xslt_file) {
	int handle;

#ifdef ENABLE_DEBUG
	session->current_task = "handle XML";
#endif

	if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
		if (errno == EACCES) {
			log_error_session(session, fb_filesystem);
			return 403;
		}
		return 404;
	} else {
		close(handle);
	}

	/* Symlink check
	 */
	if (session->host->follow_symlinks == false) {
		switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
			case fb_error:
				log_error_session(session, "error while scanning file for symlinks");
				return 500;
			case fb_not_found:
				return 404;
			case fb_no_access:
			case fb_yes:
				log_error_session(session, fb_symlink);
				return 403;
			case fb_no:
				break;
		}
	}

	return transform_xml(session, xslt_file);
}
#endif

#ifdef ENABLE_RPROXY
static int find_chunk_size(char *buffer, int size, int *chunk_size, int *chunk_left) {
	int total;
	char *c;

	if (*chunk_left > 0) {
		if (*chunk_left >= size) {
			*chunk_left -= size;
			return 0;
		}
		buffer += *chunk_left;
		size -= *chunk_left;
		*chunk_left = 0;
	}

	if ((c = strstr(buffer, "\r\n")) == NULL) {
		return -1;
	} else if (c - buffer > 10) {
		return -1;
	}

	*c = '\0';
	*chunk_size = hex_to_int(buffer);
	*c = '\r';

	if (*chunk_size == -1) {
		return -1;
	} else if (*chunk_size == 0) {
		return 0;
	}

	total = *chunk_size + 4 + (c - buffer);

	if (total < size) {
		return find_chunk_size(buffer + total, size - total, chunk_size, chunk_left);
	}

	if (total > size) {
		*chunk_left = total - size;
	}

	return 0;
}

int proxy_request(t_session *session, t_rproxy *rproxy) {
	t_rproxy_options options;
	t_rproxy_webserver webserver;
	t_rproxy_result rproxy_result;
	char buffer[RPROXY_BUFFER_SIZE + 1], *end_of_header, *str, *eol;
	char *reverse_proxy, ip_address[MAX_IP_STR_LEN + 1];
	unsigned long bytes_in_buffer = 0;
	int bytes_read, result = 200, code, poll_result, send_result, delta;
	int content_length = -1, content_read = 0, chunk_size = 0, chunk_left = 0, header_length;
	bool header_read = false, keep_reading, keep_alive, upgraded_to_websocket = false;
	bool chunked_transfer = false, send_in_chunks = false;
	struct pollfd poll_data[2];
	time_t deadline;
	t_stream stream1, stream2;
#ifdef ENABLE_TLS
	char *hostname;
#endif
#ifdef ENABLE_CACHE
	t_cached_object *cached_object;
	char *cache_buffer = NULL;
	int  cache_size = 0, cache_time = 0;
#endif

#ifdef ENABLE_DEBUG
	session->current_task = "proxy request";
#endif

#ifdef ENABLE_CACHE
	/* Search for CGI output in cache
	 */
	if (session->request_method == GET) {
		if ((cached_object = search_cache_for_rproxy_output(session)) != NULL) {
			if (session->keep_alive) {
				if (send_buffer(session, cached_object->header, cached_object->header_length) == -1) {
					result = rs_DISCONNECT;
				}
			} else {
				if (send_buffer(session, cached_object->header, cached_object->header_length - 2) == -1) {
					result = rs_DISCONNECT;
				} else if (send_buffer(session, hs_conn, 12) == -1) {
					result = rs_DISCONNECT;
				} else if (send_buffer(session, hs_concl, 7) == -1) {
					result = rs_DISCONNECT;
				} else if (send_buffer(session, "\r\n", 2) == -1) {
					result = rs_DISCONNECT;
				}
			}

			if (send_buffer(session, cached_object->content, cached_object->content_length) == -1) {
				result = rs_DISCONNECT;
			}

			done_with_cached_object(cached_object, false);

			return result;
		}
	}
#endif

	keep_alive = session->keep_alive && rproxy->keep_alive;

	/* Intialize data structure
	 */
	options.client_socket = session->client_socket;
	options.client_ip = &(session->ip_address);
	options.port = session->binding->port;
	options.method = session->method;
	options.uri = session->uri;
	options.vars = session->vars;
	options.hostname = session->hostname;
	options.http_headers = session->http_headers;
	options.body = session->body;
	options.uploaded_file = session->uploaded_file;
	options.content_length = session->content_length;
	options.remote_user = session->remote_user;
	options.custom_headers = session->host->custom_headers_rproxy;
#ifdef ENABLE_TLS
	options.use_tls = session->binding->use_tls;
#endif
#ifdef ENABLE_CACHE
	options.cache_extensions = &(session->config->cache_rproxy_extensions);
#endif

	init_rproxy_result(&rproxy_result);

	if (session->rproxy_kept_alive && ((same_ip(&(session->rproxy_addr), &(rproxy->ip_addr)) == false) || (session->rproxy_port != rproxy->port))) {
#ifdef ENABLE_TLS
		if (session->rproxy_use_tls) {
			tls_close(&(session->rproxy_ssl));
		}
#endif
		close(session->rproxy_socket);
		session->rproxy_kept_alive = false;
	}

	/* Test if kept-alive connection is still alive
	 */
	if (session->rproxy_kept_alive) {
		if (recv(session->rproxy_socket, buffer, 1, MSG_DONTWAIT | MSG_PEEK) == -1) {
			if (errno != EAGAIN) {
#ifdef ENABLE_TLS
				if (session->rproxy_use_tls) {
					tls_close(&(session->rproxy_ssl));
				}
#endif
				close(session->rproxy_socket);

				session->rproxy_kept_alive = false;
			}
		}
	}

	if (session->rproxy_kept_alive) {
		/* Use kept alive connection
		 */
		webserver.socket = session->rproxy_socket;
#ifdef ENABLE_TLS
		webserver.use_tls = session->rproxy_use_tls;

		if (webserver.use_tls) {
			memcpy(&(webserver.tls_context), &(session->rproxy_ssl), sizeof(mbedtls_ssl_context));
		}
#endif
	} else {
		/* Connect to webserver
		 */
		if (rproxy->unix_socket != NULL) {
			webserver.socket = connect_to_unix_socket(rproxy->unix_socket);
		} else {
			webserver.socket = connect_to_server(&(rproxy->ip_addr), rproxy->port);
		}
		if (webserver.socket == -1) {
			log_error_session(session, "error connecting to reverse proxy");
			return 503;
		}

#ifdef ENABLE_TLS
		webserver.use_tls = rproxy->use_tls;

		if (webserver.use_tls) {
			hostname = rproxy->hostname != NULL ? rproxy->hostname : session->hostname;
			if (tls_connect(&(webserver.tls_context), &(webserver.socket), hostname) != TLS_HANDSHAKE_OKE) {
				log_error_session(session, "TLS handshake error with reverse proxy");
				close(webserver.socket);
				return 503;
			}
		}
#endif
	}

	/* Send request to webserver
	 */
	if (send_request_to_webserver(&webserver, &options, rproxy, &rproxy_result, session->keep_alive) == -1) {
		result = -1;
	}
	session->bytes_sent += rproxy_result.bytes_sent;

	/* Read result from webserver and send to client
	 */
	deadline = time(NULL) + rproxy->timeout;

	poll_data[0].fd = webserver.socket;
	poll_data[0].events = POLL_EVENT_BITS;

	keep_reading = true;

	do {
#ifdef ENABLE_TLS
		poll_result = session->binding->use_tls ? tls_pending(&(session->tls_context)) : 0;

		if (poll_result == 0)
#endif
			poll_result = poll(poll_data, 1, 1000);

		switch (poll_result) {
			case -1:
				if (errno != EINTR) {
					result = -1;
					keep_reading = false;
					keep_alive = false;
					if (rproxy->hostname == NULL) {
						ip_to_str(&(rproxy->ip_addr), ip_address, MAX_IP_STR_LEN);
						reverse_proxy = ip_address;
					} else {
						reverse_proxy = rproxy->hostname;
					}
					log_error_session(session, "Reverse proxy connection error for %s", reverse_proxy);
				}
				break;
			case 0:
				if (time(NULL) > deadline) {
					result = 504;
					keep_reading = false;
					keep_alive = false;
					if (rproxy->hostname == NULL) {
						ip_to_str(&(rproxy->ip_addr), ip_address, MAX_IP_STR_LEN);
						reverse_proxy = ip_address;
					} else {
						reverse_proxy = rproxy->hostname;
					}
					log_error_session(session, "Reverse proxy timeout for %s", reverse_proxy);
				}
				break;
			default:
				if (RPROXY_BUFFER_SIZE - bytes_in_buffer > 0) {
#ifdef ENABLE_TLS
					if (webserver.use_tls) {
						bytes_read = tls_receive(&(webserver.tls_context), buffer + bytes_in_buffer, RPROXY_BUFFER_SIZE - bytes_in_buffer);
					} else
#endif
						bytes_read = read(webserver.socket, buffer + bytes_in_buffer, RPROXY_BUFFER_SIZE - bytes_in_buffer);
				} else {
					bytes_read = -1;
				}

				switch (bytes_read) {
					case -1:
						if (errno != EINTR) {
							result = -1;
							keep_reading = false;
							keep_alive = false;
							if (rproxy->hostname == NULL) {
								ip_to_str(&(rproxy->ip_addr), ip_address, MAX_IP_STR_LEN);
								reverse_proxy = ip_address;
							} else {
								reverse_proxy = rproxy->hostname;
							}
							log_error_session(session, "Reverse proxy read error for %s", reverse_proxy);
						}
						break;
					case 0:
						keep_reading = false;
						break;
					default:
						/* Read first line and extract return code
						 */
						bytes_in_buffer += bytes_read;
						*(buffer + bytes_in_buffer) = '\0';

						if (header_read == false) {
							/* Look for header
							 */
							if ((end_of_header = strstr(buffer, "\r\n\r\n")) != NULL) {
								header_length = end_of_header + 4 - buffer;

								if (strncmp(buffer, "HTTP/1.1 ", 9) != 0) {
									if (strncmp(buffer, "HTTP/1.0 ", 9) != 0) {
										result = 502;
										keep_reading = false;
										keep_alive = false;
										break;
									} else {
										buffer[7] = '1';
									}
								}

								if ((code = extract_http_code(buffer + 9)) != -1) {
									session->return_code = code;
								}

								if ((code >= 300) && session->host->trigger_on_cgi_status) {
									result = code;
									keep_reading = false;
									keep_alive = false;
									break;
								}

#ifdef ENABLE_CACHE
								if ((code == 200) && (session->request_method == GET)) {
									if ((cache_time = rproxy_cache_time(session, buffer, header_length)) > 0) {
										if ((cache_buffer = (char*)malloc(session->config->cache_max_filesize + 1)) != NULL) {
											*(cache_buffer + session->config->cache_max_filesize) = '\0';
										}
									}
								}

								handle_remove_header_for_rproxy_cache(session, buffer, header_length);
#endif

								/* Check for close-connection
								 */
								if (session->keep_alive) {
									if ((str = find_cgi_header(buffer, header_length, hs_conn)) != NULL) {
										str += 12;
										if (strncmp(str, "close\r\n", 7) == 0) {
											keep_alive = false;
										}
									}
								}

								/* Check for WebSocket upgrade
								 */
								if (find_cgi_header(buffer, header_length, "Connection: upgrade") != NULL) {
									if (find_cgi_header(buffer, header_length, upgrade_websocket) != NULL) {
										upgraded_to_websocket = true;
										keep_reading = false;
									}
								}

								if (upgraded_to_websocket == false) {
									delta = remove_header(buffer, hs_conn, &header_length, &bytes_in_buffer);
									end_of_header -= delta;
									bytes_read -= delta;
								}

								if ((session->request_method == HEAD) || empty_body_because_of_http_status(code)) {
									content_length = 0;
								} else if (keep_alive) {
									/* Parse content length
									 */
									if ((str = find_cgi_header(buffer, header_length, hs_conlen)) != NULL) {
										str += 16;
										if ((eol = strchr(str, '\r')) != NULL) {
											*eol = '\0';
											content_length = str_to_int(str);
											*eol = '\r';
										}
									}

									/* Determine if is chunked transfer encoding
									 */
									if (find_cgi_header(buffer, header_length, hs_chunked) != NULL) {
										chunked_transfer = true;
										content_length = -1;
										chunk_size = header_length;
										chunk_left = chunk_size;
									}
								} else if (session->keep_alive &&
								          (find_cgi_header(buffer, header_length, hs_conlen) == NULL) &&
									      (find_cgi_header(buffer, header_length, hs_chunked) == NULL)) {
									/* We need to forward result in chunks
									 */
									if (send_buffer(session, buffer, header_length - 2) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									} else if (send_buffer(session, hs_chunked, 28) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									} else if (send_buffer(session, "\r\n", 2) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									} else if (send_buffer(session, NULL, 0) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									}

#ifdef ENABLE_CACHE
									/* Add output to cache buffer
									 */
									if (cache_buffer != NULL) {
										if ((off_t)(cache_size + header_length) > session->config->cache_max_filesize) {
											clear_free(cache_buffer, cache_size);
											cache_buffer = NULL;
										} else {
											memcpy(cache_buffer + cache_size, buffer, header_length);
											cache_size += header_length;
											*(cache_buffer + cache_size) = '\0';
										}
									}
#endif

									if ((content_read = bytes_in_buffer - header_length) > 0) {
										memmove(buffer, end_of_header + 4, content_read);
									}
									bytes_in_buffer = content_read;
									send_in_chunks = true;
								}

								if (send_in_chunks == false) {
									content_read = bytes_in_buffer - header_length;
								}

								header_read = true;

								if (bytes_in_buffer == 0) {
									continue;
								}
							} else if (bytes_in_buffer == RPROXY_BUFFER_SIZE) {
								result = -1;
								keep_reading = false;
								keep_alive = false;
								break;
							} else {
								continue;
							}
						} else {
							/* Dealing with body
							 */
							content_read += bytes_read;
						}

						if (content_read == content_length) {
							keep_reading = false;
						}

						/* Send buffer content
						 */
						if (send_in_chunks) {
							send_result = send_chunk(session, buffer, bytes_in_buffer);
						} else {
							send_result = send_buffer(session, buffer, bytes_in_buffer);
						}

						if (send_result == -1) {
							result = -1;
							keep_reading = false;
							keep_alive = false;
							break;
						}

#ifdef ENABLE_CACHE
						/* Add output to cache buffer
						 */
						if (cache_buffer != NULL) {
							if ((off_t)(cache_size + bytes_in_buffer) > session->config->cache_max_filesize) {
								clear_free(cache_buffer, cache_size);
								cache_buffer = NULL;
							} else {
								memcpy(cache_buffer + cache_size, buffer, bytes_in_buffer);
								cache_size += bytes_in_buffer;
								*(cache_buffer + cache_size) = '\0';
							}
						}
#endif

						if (chunked_transfer) {
							if (find_chunk_size(buffer, bytes_in_buffer, &chunk_size, &chunk_left) == -1) {
								keep_reading = false;
								keep_alive = false;
							} else if (chunk_size == 0) {
								keep_reading = false;
							}
						}

						bytes_in_buffer = 0;
						session->data_sent = true;
				}
		}
	} while (keep_reading);

	if (send_in_chunks && ((result < 300) || (session->host->trigger_on_cgi_status == false))) {
		send_chunk(session, NULL, 0);
	}

	if (upgraded_to_websocket) {
		/* Connection upgraded to Websocket
		 */
		if (send_in_chunks == false) {
			send_buffer(session, NULL, 0);
		}

		stream1.socket = webserver.socket;
#ifdef ENABLE_TLS
		stream1.use_tls = webserver.use_tls;
		stream1.tls_context = &(webserver.tls_context);
#endif

		stream2.socket = session->client_socket;
#ifdef ENABLE_TLS
		stream2.use_tls = session->binding->use_tls;
		stream2.tls_context = &(session->tls_context);
#endif

		result = link_streams(&stream1, &stream2, rproxy->timeout);

		keep_alive = false;
		session->return_code = 101;
#ifdef ENABLE_CACHE
		cache_buffer = NULL;
#endif
	}

	session->time = time(NULL);

#ifdef ENABLE_CACHE
	if (cache_buffer != NULL) {
		add_rproxy_output_to_cache(session, cache_buffer, cache_size, cache_time);
		clear_free(cache_buffer, cache_size);
	}
#endif

	if (keep_alive == false) {
		/* Close connection to webserver
		 */
#ifdef ENABLE_TLS
		if (webserver.use_tls) {
			tls_close(&(webserver.tls_context));
		}
#endif
		close(webserver.socket);
	} else if (session->rproxy_kept_alive == false) {
		/* Keep connection alive
		 */
		memcpy(&(session->rproxy_addr), &(rproxy->ip_addr), sizeof(t_ip_addr));
		session->rproxy_port = rproxy->port;
		session->rproxy_socket = webserver.socket;
#ifdef ENABLE_TLS
		session->rproxy_use_tls = webserver.use_tls;
		if (session->rproxy_use_tls) {
			memcpy(&(session->rproxy_ssl), &(webserver.tls_context), sizeof(mbedtls_ssl_context));
		}
#endif
	}

	session->rproxy_kept_alive = keep_alive;

	return result;
}
#endif

static int add_to_buffer(char *str, char *buffer, size_t *size, size_t max_size) {
	size_t str_len;

	str_len = strlen(str);
	if (*size + str_len >= max_size) {
		return -1;
	}

	memcpy(buffer + *size, str, str_len);
	*size += str_len;
	*(buffer + *size) = '\0';

	return 0;
}

int forward_to_websocket(t_session *session) {
	t_websocket *ws;
	int result = -1, ws_socket;
	size_t size;
	t_http_header *http_header;
	char buffer[WS_BUFFER_SIZE];
	t_stream stream1, stream2;
#ifdef ENABLE_TLS
	mbedtls_ssl_context ws_tls_context;
#endif

	ws = session->host->websockets;
	while (ws != NULL) {
		if (matches_charlist(session->uri, &(ws->path))) {
			break;
		} else if (in_charlist("*", &(ws->path))) {
			break;
		}
		ws = ws->next;
	}

	if (ws == NULL) {
		return -1;
	}

	if (ws->unix_socket != NULL) {
		ws_socket = connect_to_unix_socket(ws->unix_socket);
	} else {
		ws_socket = connect_to_server(&(ws->ip_address), ws->port);
	}

	if (ws_socket == -1) {
		log_error_session(session, "error connecting to websocket");
		return 503;
	}

#ifdef ENABLE_TLS
	if (ws->use_tls) {
		if (tls_connect(&ws_tls_context, &ws_socket, NULL) != TLS_HANDSHAKE_OKE) {
			log_error_session(session, "TLS handshake error with websocket");
			close(ws_socket);
			return -1;
		}
	}
#endif

	size = 0;
	add_to_buffer("GET ", buffer, &size, WS_BUFFER_SIZE);
	if (add_to_buffer(session->uri, buffer, &size, WS_BUFFER_SIZE) == -1) {
		goto ws_error;
	}

	if (add_to_buffer(" HTTP/1.1\r\n", buffer, &size, WS_BUFFER_SIZE) == -1) {
		goto ws_error;
	}

	http_header = session->http_headers;
	while (http_header != NULL) {
		if (add_to_buffer(http_header->data, buffer, &size, WS_BUFFER_SIZE) == -1) {
			goto ws_error;
		}

		if (add_to_buffer("\r\n", buffer, &size, WS_BUFFER_SIZE) == -1) {
			goto ws_error;
		}

		http_header = http_header->next;
	}

	if (add_to_buffer("\r\n", buffer, &size, WS_BUFFER_SIZE) == -1) {
		goto ws_error;
	}

#ifdef ENABLE_TLS
	if (ws->use_tls) {
		if (tls_send_buffer(&ws_tls_context, buffer, size) == -1) {
			goto ws_error;
		}
	} else
#endif
		if (write_buffer(ws_socket, buffer, size) == -1) {
			goto ws_error;
		}

	stream1.socket = ws_socket;
#ifdef ENABLE_TLS
	stream1.use_tls = ws->use_tls;
	stream1.tls_context = &ws_tls_context;
#endif

	stream2.socket = session->client_socket;
#ifdef ENABLE_TLS
	stream2.use_tls = session->binding->use_tls;
	stream2.tls_context = &(session->tls_context);
#endif

	result = link_streams(&stream1, &stream2, ws->timeout);

ws_error:
#ifdef ENABLE_TLS
	if (ws->use_tls) {
		tls_close(&ws_tls_context);
	}
#endif
	close(ws_socket);

	return result;
}
