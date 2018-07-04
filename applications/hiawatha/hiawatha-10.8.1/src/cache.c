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

#ifdef ENABLE_CACHE

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include "alternative.h"
#include "libfs.h"
#include "libstr.h"
#include "session.h"
#include "cache.h"
#include "cgi.h"
#include "memdbg.h"

#define MAX_CACHE_INDEX 250
#define EXTENSION_SIZE 10

extern char *hs_conlen;
extern char *hs_chunked;

static t_cached_object *cache[MAX_CACHE_INDEX];
static pthread_mutex_t cache_mutex[MAX_CACHE_INDEX];
static pthread_mutex_t cache_size_mutex;
static volatile off_t cache_size;

/* ===============================================
 *
 * Internal functions
 */
static int cache_index(char *filename) {
	int index = 0;

	if (filename == NULL) {
		return -1;
	}

	while (*filename != '\0') {
		index += (unsigned char)*filename;
		filename++;
	}

	return abs(index) % MAX_CACHE_INDEX;
}

static t_cached_object *remove_from_cache(t_cached_object *object, int index) {
	t_cached_object *next;

	if (object->prev != NULL) {
		object->prev->next = object->next;
	}
	if ((next = object->next) != NULL) {
		object->next->prev = object->prev;
	}

	pthread_mutex_lock(&cache_size_mutex);
	cache_size -= (object->header_length + object->content_length);
	pthread_mutex_unlock(&cache_size_mutex);

	if (object == cache[index]) {
		cache[index] = object->next;
	}

	check_clear_free(object->header, object->header_length);
	clear_free(object->content, object->content_length);
	free(object->file);
	free(object);

	return next;
}

static bool add_object_to_cache(t_cached_object *object) {
	int index;
	t_cached_object *search;

	if (object == NULL) {
		return false;
	} else if ((index = cache_index(object->file)) == -1) {
		return false;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object->prev = NULL;
	object->next = cache[index];
	if (cache[index] != NULL) {
		cache[index]->prev = object;

		search = cache[index];
		while (search != NULL) {
			if (strcmp(search->file, object->file) == 0) {
				search->deadline = 0;
				break;
			}
			search = search->next;
		}
	}
	cache[index] = object;

	pthread_mutex_lock(&cache_size_mutex);
	cache_size += (object->header_length + object->content_length);
	pthread_mutex_unlock(&cache_size_mutex);

	pthread_mutex_unlock(&cache_mutex[index]);

	return true;
}

/* ===============================================
 *
 * Internal CGI and Reverse Proxy functions
 */
static char *make_url(t_session *session, char *request_uri) {
	char *url;
	size_t len, len_ru;

	len = strlen(*(session->host->hostname.item));
	if (request_uri == NULL) {
		request_uri = session->request_uri;
	}

	len_ru = strlen(request_uri);
	if ((url = (char*)malloc(len + len_ru + 1)) == NULL) {
		return NULL;
	}

	memcpy(url, *(session->host->hostname.item), len);
	strncpy(url + len, request_uri, len_ru + 1);

	return url;
}

static void secure_header(char *buffer, int size) {
	char *eoh, *pos;
	int header_length;

	if ((eoh = strnstr(buffer, "\r\n\r\n", size)) == NULL) {
		return;
	}

	header_length = eoh + 4 - buffer;

	/* Remove cookies
	 */
	while ((pos = strncasestr(buffer, "Set-Cookie:", header_length)) != NULL) {
		strcpy(pos, "X-Empty: ");
		pos += 9;
		do {
			*(pos++) = 'x';
		} while ((*pos != '\r') && (*pos != '\0'));
	}
}

static t_cached_object *add_output_to_cache(t_session *session, char *output, int size, int time, t_cot_type cot_type) {
	t_cached_object *object;
	char *header, *content, *eoh, conlen[64];
	int header_length, content_length, conlen_len = 0;
	bool add_conlen;

	if ((output == NULL) || (size == 0)) {
		return NULL;
	}

	if ((eoh = strstr(output, "\r\n\r\n")) == NULL) {
		return NULL;
	}

	header_length = eoh + 4 - output;
	content_length = size - header_length;

	add_conlen = true;
	if (strncasestr(output, hs_chunked, header_length) != NULL) {
		add_conlen = false;
	} else if (strncasestr(output, hs_conlen, header_length) != NULL) {
		add_conlen = false;
	}

	if (add_conlen) {
		if ((conlen_len = snprintf(conlen, 63, "%s%d\r\n", hs_conlen, content_length)) >= 63) {
			return NULL;
		}
	}

	if ((header = (char*)malloc(header_length + conlen_len + 1)) == NULL) {
		return NULL;
	}

	if ((content = (char*)malloc(content_length + 1)) == NULL) {
		free(header);
		return NULL;
	}

	if (add_conlen) {
		memcpy(header, output, header_length - 2);
		memcpy(header + header_length - 2, conlen, conlen_len);
		memcpy(header + header_length - 2 + conlen_len, "\r\n", 2);
		*(header + header_length + conlen_len) = '\0';
	} else {
		memcpy(header, output, header_length);
		*(header + header_length) = '\0';
	}

	memcpy(content, output + header_length, content_length);
	*(content + content_length) = '\0';

	secure_header(header, header_length);

	if ((object = (t_cached_object*)malloc(sizeof(t_cached_object))) == NULL) {
		clear_free(header, header_length);
		clear_free(content, content_length);
		return NULL;
	} else if ((object->file = make_url(session, NULL)) == NULL) {
		clear_free(header, header_length);
		clear_free(content, content_length);
		free(object);
		return NULL;
	}

	object->deadline = session->time + time;
	object->in_use = 0;
	object->type = cot_type;
	object->header = header;
	object->header_length = header_length + conlen_len;
	object->content = content;
	object->content_length = content_length;
	copy_ip(&(object->last_ip), &(session->ip_address));

	if (add_object_to_cache(object) == false) {
		clear_free(header, header_length);
		clear_free(content, content_length);
		free(object->file);
		free(object);

		return NULL;
	}

	return object;
}

static t_cached_object *search_cache_for_output(t_session *session, t_cot_type cot_type) {
	t_cached_object *object, *result = NULL;
	char *url;
	int index;

	if ((url = make_url(session, NULL)) == NULL) {
		return NULL;
	} else if ((index = cache_index(url)) == -1) {
		free(url);
		return NULL;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object = cache[index];
	while (object != NULL) {
		if (object->type == cot_type) {
			if (strcmp(object->file, url) == 0) {
				if (object->deadline > session->time) {
					object->in_use++;
					result = object;
				} else if (object->in_use <= 0) {
					remove_from_cache(object, index);
				}
				break;
			}
		}
		object = object->next;
	}

	pthread_mutex_unlock(&cache_mutex[index]);

	free(url);

	return result;
}

static void flush_output_cache(t_session *session, t_cot_type cot_type) {
	t_cached_object *object;
	int index;
	size_t len;

	for (index = 0; index < MAX_CACHE_INDEX; index++) {
		pthread_mutex_lock(&cache_mutex[index]);

		object = cache[index];
		while (object != NULL) {
			if (object->type == cot_type) {
				len = strlen(*(session->host->hostname.item));
				if (strncmp(object->file, *(session->host->hostname.item), len) == 0) {
					if (*(object->file + len) == '/') {
						if (object->in_use <= 0) {
							object = remove_from_cache(object, index);
							continue;
						} else {
							object->deadline = 0;
						}
					}
				}
			}
			object = object->next;
		}

		pthread_mutex_unlock(&cache_mutex[index]);
	}
}

static void remove_output_from_cache(t_session *session, char *request_uri, t_cot_type cot_type) {
	t_cached_object *object;
	char *url;
	int index;

	if ((url = make_url(session, request_uri)) == NULL) {
		return;
	} else if ((index = cache_index(url)) == -1) {
		free(url);
		return;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object = cache[index];
	while (object != NULL) {
		if (object->type == cot_type) {
			if (strcmp(object->file, url) == 0) {
				if (object->in_use <= 0) {
					remove_from_cache(object, index);
				} else {
					object->deadline = 0;
				}
				break;
			}
		}
		object = object->next;
	}

	pthread_mutex_unlock(&cache_mutex[index]);

	free(url);
}

static void handle_remove_from_cache_header(t_session *session, char *buffer, int size, t_cot_type cot_type) {
	char *begin, *end;

	if ((begin = find_cgi_header(buffer, size, "X-Hiawatha-Cache-Remove:")) == NULL) {
		return;
	}

	begin += 25;
	while (*begin == ' ') {
		begin++;
	}

	end = begin;
	while ((*end != '\r') && (*end != '\0')) {
		end++;
	}
	if (*end == '\r') {
		*end = '\0';
		if (strcmp(begin, "all") == 0) {
			flush_output_cache(session, cot_type);
		} else {
			remove_output_from_cache(session, begin, cot_type);
		}
		*end = '\r';
	}
}

/* ===============================================
 *
 * Generic functions
 */
int init_cache_module(void) {
	int index;

	for (index = 0; index < MAX_CACHE_INDEX; index++) {
		cache[index] = NULL;
		if (pthread_mutex_init(&cache_mutex[index], NULL) != 0) {
			return -1;
		}
	}

	if (pthread_mutex_init(&cache_size_mutex, NULL) != 0) {
		return -1;
	}
	cache_size = 0;

	return 0;
}

void done_with_cached_object(t_cached_object *object, bool remove_object) {
	if (remove_object) {
		object->deadline = 0;
	}
	object->in_use--;
}

void manage_cache(time_t now) {
	t_cached_object *object;
	int index;

	for (index = 0; index < MAX_CACHE_INDEX; index++) {
		pthread_mutex_lock(&cache_mutex[index]);

		object = cache[index];
		while (object != NULL) {
			if (now > object->deadline) {
				if (object->in_use <= 0) {
					object = remove_from_cache(object, index);
					continue;
				}
			}
			object = object->next;
		}

		pthread_mutex_unlock(&cache_mutex[index]);
	}
}

int clear_cache() {
	t_cached_object *object, *list;
	int i, removed = 0;

	for (i = 0; i < MAX_CACHE_INDEX; i++) {
		pthread_mutex_lock(&cache_mutex[i]);

		list = cache[i];
		cache[i] = NULL;
		while (list != NULL) {
			object = list;
			list = list->next;

			if (object->in_use == 0) {
				/* Object unused, so remove
				 */
				pthread_mutex_lock(&cache_size_mutex);
				cache_size -= (object->header_length + object->content_length);
				pthread_mutex_unlock(&cache_size_mutex);

				check_clear_free(object->header, object->header_length);
				clear_free(object->content, object->content_length);
				free(object->file);
				free(object);

				removed++;
			} else {
				/* Object in use, put back in list
				 */
				object->next = cache[i];
				cache[i] = object;
			}
		}

		pthread_mutex_unlock(&cache_mutex[i]);
	}

	return removed;
}

#ifdef ENABLE_TOMAHAWK
void print_cache_list(FILE *fp) {
	t_cached_object *object;
	int i, files = 0, secs;
	off_t size = 0;
	time_t now;

	now = time(NULL);

	/* File cache
	 */
	for (i = 0; i < MAX_CACHE_INDEX; i++) {
		pthread_mutex_lock(&cache_mutex[i]);

		object = cache[i];
		while (object != NULL) {
			fprintf(fp, "  Filename : %s\n", object->file);
			fprintf(fp, "  File size: %.2f kB\n", (float)(object->header_length + object->content_length) / KILOBYTE);
			if ((secs = object->deadline - now) > 0) {
				fprintf(fp, "  Time left: %d seconds\n\n", secs);
			} else {
				fprintf(fp, "  File marked for removal from cache\n\n");
			}
			files++;
			size += object->header_length + object->content_length;
			object = object->next;
		}

		pthread_mutex_unlock(&cache_mutex[i]);
	}

	fprintf(fp, "  Total: %.2f MB in %d cache objects.\n", (float)(size) / MEGABYTE, files);
}

off_t size_of_cache(void) {
	return cache_size;
}
#endif

/* ===============================================
 *
 * File cache functions
 */
t_cached_object *add_file_to_cache(t_session *session, char *file) {
	t_cached_object *object;
	struct stat status;
	off_t size;
	int fd;
	ssize_t bytes_read, bytes_total = 0;

	if (file == NULL) {
		return NULL;
	} else if (stat(file, &status) == -1) {
		return NULL;
	} else if ((size = status.st_size) <= 0) {
		return NULL;
	} else if (size > session->config->cache_max_filesize) {
		return NULL;
	} else if (cache_size + size > session->config->cache_size) {
		return NULL;
	} else if ((object = (t_cached_object*)malloc(sizeof(t_cached_object))) == NULL) {
		return NULL;
	} else if ((object->file = strdup(file)) == NULL) {
		free(object);
		return NULL;
	} else if ((object->content = (char*)malloc(size)) == NULL) {
		free(object->file);
		free(object);
		return NULL;
	}

	if ((fd = open(file, O_RDONLY)) != -1) {
		while ((off_t)bytes_total < size) {
			if ((bytes_read = read(fd, object->content + bytes_total, size - bytes_total)) == -1) {
				if (errno != EINTR) {
					clear_free(object->content, size);
					free(object->file);
					free(object);
					close(fd);

					return NULL;
				}
			} else {
				bytes_total += bytes_read;
			}
		}
		close(fd);
	} else {
		clear_free(object->content, size);
		free(object->file);
		free(object);

		return NULL;
	}

	object->header = NULL;
	object->header_length = 0;
	object->content_length = size;
	object->last_changed = status.st_mtime;
	object->deadline = session->time + TIME_IN_CACHE;
	object->in_use = 1;
	object->type = cot_file;
	copy_ip(&(object->last_ip), &(session->ip_address));

	if (add_object_to_cache(object) == false) {
		clear_free(object->content, size);
		free(object->file);
		free(object);

		return NULL;
	}

	return object;
}

t_cached_object *search_cache_for_file(t_session *session, char *file) {
	t_cached_object *object, *result = NULL;
	struct stat status;
	off_t size;
	int index;

	if (file == NULL) {
		return NULL;
	} else if ((size = filesize(file)) == -1) {
		return NULL;
	} else if ((index = cache_index(file)) == -1) {
		return NULL;
	}

	pthread_mutex_lock(&cache_mutex[index]);

	object = cache[index];
	while (object != NULL) {
		if ((object->type == cot_file) && (object->content_length == size)) {
			if (strcmp(object->file, file) == 0) {
				if (stat(file, &status) == 0) {
					if ((object->deadline > session->time) && (status.st_mtime == object->last_changed)) {
						if (same_ip(&(object->last_ip), &(session->ip_address)) == false) {
							if ((object->deadline += TIME_IN_CACHE) > (session->time + MAX_CACHE_TIMER)) {
								object->deadline = session->time + MAX_CACHE_TIMER;
							}
							copy_ip(&(object->last_ip), &(session->ip_address));
						}
						object->in_use++;
						result = object;
					} else if (object->in_use <= 0) {
						remove_from_cache(object, index);
					}
				} else if (object->in_use <= 0) {
					remove_from_cache(object, index);
				}
				break;
			}
		}
		object = object->next;
	}

	pthread_mutex_unlock(&cache_mutex[index]);

	return result;
}

/* ===============================================
 *
 * CGI functions
 */
int cgi_cache_time(char *buffer, int size) {
	char *begin, *end;
	int cache_time;

	if ((begin = find_cgi_header(buffer, size, "X-Hiawatha-Cache:")) == NULL) {
		return 0;
	}

	begin += 18;
	while (*begin == ' ') {
		begin++;
	}

	end = begin;
	while ((*end != '\r') && (*end != '\0')) {
		end++;
	}
	if (*end == '\0') {
		return 0;
	}

	*end = '\0';
	cache_time = str_to_int(begin);
	*end = '\r';

	if (cache_time < MIN_CGI_CACHE_TIMER) {
		return 0;
	}

	if (cache_time > MAX_CGI_CACHE_TIMER) {
		cache_time = MAX_CGI_CACHE_TIMER;
	}

	return cache_time;
}

t_cached_object *search_cache_for_cgi_output(t_session *session) {
	return search_cache_for_output(session, cot_cgi);
}

t_cached_object *add_cgi_output_to_cache(t_session *session, char *output, int size, int time) {
	return add_output_to_cache(session, output, size, time, cot_cgi);
}

void handle_remove_header_for_cgi_cache(t_session *session, char *buffer, int size) {
	handle_remove_from_cache_header(session, buffer, size, cot_cgi);
}

/* ===============================================
 *
 * Reverse Proxy functions
 */
#ifdef ENABLE_RPROXY
int rproxy_cache_time(t_session *session, char *buffer, int size) {
	int cache_time;
	char *value, *no_cache = "no-cache", extension[EXTENSION_SIZE];

	if ((cache_time = cgi_cache_time(buffer, size)) > 0) {
		return cache_time;
	}

	if (extension_from_uri(session->request_uri, extension, EXTENSION_SIZE) == false) {
		return 0;
	}

	if (in_charlist(extension, &(session->config->cache_rproxy_extensions)) == false) {
		return 0;
	}

	if ((value = get_http_header("Cache-Control:", session->http_headers)) != NULL) {
		if (strstr(value, no_cache) != NULL) {
			return 0;
		}
	}

	if ((value = get_http_header("Pragma:", session->http_headers)) != NULL) {
		if (strstr(value, no_cache) != NULL) {
			return 0;
		}
	}

	return TIME_IN_CACHE;
}

t_cached_object *search_cache_for_rproxy_output(t_session *session) {
	return search_cache_for_output(session, cot_rproxy);
}

t_cached_object *add_rproxy_output_to_cache(t_session *session, char *output, int size, int time) {
	return add_output_to_cache(session, output, size, time, cot_rproxy);
}

void handle_remove_header_for_rproxy_cache(t_session *session, char *buffer, int size) {
	handle_remove_from_cache_header(session, buffer, size, cot_rproxy);
}

#endif

#endif
