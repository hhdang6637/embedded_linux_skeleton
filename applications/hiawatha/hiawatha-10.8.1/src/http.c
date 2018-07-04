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
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "global.h"
#include "alternative.h"
#include "session.h"
#include "libstr.h"
#include "liblist.h"
#include "ip.h"
#include "tomahawk.h"
#include "log.h"
#include "monitor.h"
#include "memdbg.h"
#include "send.h"

#define REQUEST_BUFFER_CHUNK     4 * KILOBYTE
#define NO_REQUEST_LIMIT_TIME  300
#define NO_REQUEST_LIMIT_SIZE   32 * MEGABYTE

extern char *hs_conlen;
extern char *hs_chunked;
extern char *hs_forwarded;
extern char *hs_x_forwarded_for;

char *upgrade_websocket = "Upgrade: websocket";

/* Detect chunked upload progress
 */
static int all_chunks_uploaded(char *buffer, int size, long *chunk_size_pos) {
	int chunk_size, len;
	char *end;

	if (size == 0) {
		return 0;
	} else if (*chunk_size_pos >= size) {
		return -1;
	}

	if ((end = strstr(buffer + *chunk_size_pos, "\r\n")) == NULL) {
		return 0;
	}
	*end = '\0';
	chunk_size = hex_to_int(buffer + *chunk_size_pos);
	*end = '\r';

	if (chunk_size == -1) {
		return -1;
	}

	len = (end - buffer) + chunk_size + 4;
	if (chunk_size == 0) {
		if (size >= len) {
			return 1;
		}
	} else if (size > len) {
		*chunk_size_pos = len;
		return all_chunks_uploaded(buffer, size, chunk_size_pos);
	}

	return 0;
}

/* Merge chunks to one single content block
 */
static long merge_chunks(char *buffer, long size, long *bytes_in_buffer) {
	long chunk_size, chunk_hf_len, content_length = 0;
	char *end, *destination;

	destination = buffer;

	do {
		if ((end = strstr(buffer, "\r\n")) == NULL) {
			return -1;
		}
		*end = '\0';
		chunk_size = hex_to_int(buffer);
		*end = '\r';

		if (chunk_size == -1) {
			return -1;
		}

		chunk_hf_len = end + 4 - buffer;

		if (chunk_hf_len + chunk_size > size) {
			return -1;
		}

		if (chunk_size == 0) {
			size -= chunk_hf_len;
			if (size > 0) {
				memmove(destination, end + 4, size);
			}
			*bytes_in_buffer -= chunk_hf_len;
			*(destination + size) = '\0';
		} else {
			memmove(destination, end + 2, chunk_size);
			destination += chunk_size;
			size -= chunk_hf_len + chunk_size;
			buffer += chunk_hf_len + chunk_size;
			content_length += chunk_size;
			*bytes_in_buffer -= chunk_hf_len;
		}
	} while (chunk_size > 0);

	return content_length;
}

/* Read the request from a client socket.
 */
int fetch_request(t_session *session) {
	char *new_reqbuf, *strstart, *strend;
	long max_request_size, bytes_read, header_length = -1, content_length = -1, uploaded_size = 0, chunk_size_pos = 0;
	int result = 200, write_bytes, poll_result, upload_handle = -1, retval;
	time_t deadline;
	struct pollfd poll_data;
	bool keep_reading = true, store_on_disk = false, chunked_request = false;

	if (session->request_limit == false) {
		if (session->binding->time_for_request > NO_REQUEST_LIMIT_TIME) {
			deadline = session->time + session->binding->time_for_request;
		} else {
			deadline = session->time + NO_REQUEST_LIMIT_TIME;
		}
		if (session->binding->max_request_size > NO_REQUEST_LIMIT_SIZE) {
			max_request_size = session->binding->max_request_size;
		} else {
			max_request_size = NO_REQUEST_LIMIT_SIZE;
		}
	} else if (session->kept_alive == 0) {
		deadline = session->time + session->binding->time_for_1st_request;
		max_request_size = session->binding->max_request_size;
	} else {
		deadline = session->time + session->binding->time_for_request;
		max_request_size = session->binding->max_request_size;
	}

	do {
		/* Check if requestbuffer contains a complete request.
		 */
		if (session->request != NULL) {
			if (header_length == -1) {
				if ((strstart = strstr(session->request, "\r\n\r\n")) != NULL) {
					*(strstart + 2) = '\0';
					header_length = strstart + 4 - session->request;
					session->header_length = header_length;

					determine_request_method(session);
					store_on_disk = (session->request_method == PUT) && session->binding->enable_alter;

					if (store_on_disk) {
	 					if ((session->uploaded_file = (char*)malloc(session->config->upload_directory_len + 15)) != NULL) {
							memcpy(session->uploaded_file, session->config->upload_directory, session->config->upload_directory_len);
							memcpy(session->uploaded_file + session->config->upload_directory_len, "/upload_XXXXXX", 15);

							umask(S_IWGRP | S_IWOTH);
							if ((upload_handle = mkstemp(session->uploaded_file)) == -1) {
								free(session->uploaded_file);
								session->uploaded_file = NULL;
							}
						}
						if (session->uploaded_file == NULL) {
							log_error_session(session, "can't create temporary file for PUT request");
							result = 500;
							break;
						}

						uploaded_size = session->bytes_in_buffer - header_length;
						if (write_buffer(upload_handle, session->request + header_length, uploaded_size) == -1) {
							result = 500;
							break;
						}
						session->bytes_in_buffer = header_length;
					}

					/* Handle 100-continue
					 */
					if (strnstr(session->request, "Expect: 100-continue\r\n", header_length) != NULL) {
						send_buffer(session, "HTTP/1.1 100 Continue\r\n\r\n", 25);
						send_buffer(session, NULL, 0);
					}
				}
			}

			if (header_length != -1) {
				if ((content_length == -1) && (chunked_request == false)) {
					if ((strstart = strcasestr(session->request, hs_conlen)) != NULL) {
						/* Request has Content-Length
						 */
						strstart += 16;
						if ((strend = strstr(strstart, "\r\n")) != NULL) {
							*strend = '\0';
							content_length = str_to_int(strstart);
							*strend = '\r';
							if ((content_length < 0) || (INT_MAX - content_length - 2 <= header_length)) {
								result = 500;
								break;
							}

							session->content_length = content_length;

							if (store_on_disk) {
								/* Write to file on disk
								 */
								if (content_length > session->binding->max_upload_size) {
									result = 413;
									break;
								}

								session->buffer_size = header_length + REQUEST_BUFFER_CHUNK;
								if ((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
									session->request = new_reqbuf;
								} else {
									session->error_cause = ec_SOCKET_READ_ERROR;
									result = -1;
									break;
								}
							} else {
								/* Read into memory
								 */
								if (header_length + content_length > max_request_size) {
									session->error_cause = ec_MAX_REQUESTSIZE;
									result = -1;
									break;
								}

								if (header_length + content_length > session->buffer_size) {
									session->buffer_size = header_length + content_length;
									if ((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
										session->request = new_reqbuf;
									} else {
										session->error_cause = ec_SOCKET_READ_ERROR;
										result = -1;
										break;
									}
								}
							}
						}
					} else if (strcasestr(session->request, hs_chunked) != NULL) {
						/* Chunked transfer encoding
						 */
						if (store_on_disk) {
							log_error_session(session, "Chunked transfer encoding for PUT requests not supported.");
							result = -1;
							break;
						}
						chunked_request = true;
						chunk_size_pos = 0;
					} else {
						/* No content
						 */
						session->content_length = 0;
						if (store_on_disk) {
							result = 411;
						}
						break;
					}
				}

				if (content_length > -1) {
					if (store_on_disk) {
						if (uploaded_size == content_length) {
							/* Received a complete PUT request */
							break;
						}
					} else {
						if (session->bytes_in_buffer >= header_length + content_length) {
							/* Received a complete request */
							break;
						}
					}
				} else if (chunked_request) {
					/* All chunks uploaded
					 */
					retval = all_chunks_uploaded(session->request + session->header_length,
					                             session->bytes_in_buffer - session->header_length,
					                             &chunk_size_pos);
					if (retval == -1) {
						result = 400;
						break;
					} else if (retval == 1) {
						if ((session->content_length = merge_chunks(session->request + session->header_length,
						                                            session->bytes_in_buffer - session->header_length,
							                                        &(session->bytes_in_buffer))) == -1) {
							result = -1;
						}
						break;
					}
				}
			}
		}

#ifdef ENABLE_TLS
		poll_result = session->binding->use_tls ? tls_pending(&(session->tls_context)) : 0;

		if (poll_result == 0) {
#endif
			poll_data.fd = session->client_socket;
			poll_data.events = POLL_EVENT_BITS;
			poll_result = poll(&poll_data, 1, 1000);
#ifdef ENABLE_TLS
		}
#endif

		switch (poll_result) {
			case -1:
				if (errno != EINTR) {
					if (session->bytes_in_buffer == 0) {
						session->error_cause = ec_CLIENT_DISCONNECTED;
					} else {
						session->error_cause = ec_SOCKET_READ_ERROR;
					}
					result = -1;
					keep_reading = false;
				}
				break;
			case 0:
				if (session->force_quit) {
					session->error_cause = ec_FORCE_QUIT;
					result = -1;
					keep_reading = false;
				} else if (time(NULL) > deadline) {
					session->error_cause = ec_TIMEOUT;
					result = -1;
					keep_reading = false;
				}
				break;
			default:
				if ((content_length == -1) && ((session->buffer_size - session->bytes_in_buffer) < 256)) {
					session->buffer_size += REQUEST_BUFFER_CHUNK;
					if ((new_reqbuf = (char*)realloc(session->request, session->buffer_size + 1)) != NULL) {
						session->request = new_reqbuf;
					} else {
						session->error_cause = ec_SOCKET_READ_ERROR;
						result = -1;
						keep_reading = false;
						break;
					}
				}

				/* Read from socket.
				 */
#ifdef ENABLE_TLS
				if (session->binding->use_tls) {
					bytes_read = tls_receive(&(session->tls_context), session->request + session->bytes_in_buffer,
									session->buffer_size - session->bytes_in_buffer);
				} else
#endif
					bytes_read = recv(session->client_socket, session->request + session->bytes_in_buffer,
									session->buffer_size - session->bytes_in_buffer, 0);
				switch (bytes_read) {
					case -1:
						if (errno != EINTR) {
							if (session->bytes_in_buffer == 0) {
								session->error_cause = ec_CLIENT_DISCONNECTED;
							} else {
								session->error_cause = ec_SOCKET_READ_ERROR;
							}
							result = -1;
							keep_reading = false;
						}
						break;
					case 0:
						session->error_cause = ec_CLIENT_DISCONNECTED;
						result = -1;
						keep_reading = false;
						break;
					default:
						if (store_on_disk) {
							/* Write to file on disk
							 */
							write_bytes = bytes_read;
							if (uploaded_size + bytes_read > content_length) {
								write_bytes -= ((uploaded_size + bytes_read) - content_length);
							}
							if (write_buffer(upload_handle, session->request + header_length, write_bytes) == -1) {
								result = 500;
								keep_reading = false;
								break;
							}
							if ((uploaded_size += write_bytes) > session->binding->max_upload_size) {
								keep_reading = false;
								result = 413;
								break;
							}
							if (write_bytes < bytes_read) {
								memmove(session->request + header_length, session->request + header_length + write_bytes, bytes_read - write_bytes);
								session->bytes_in_buffer += bytes_read - write_bytes;
								keep_reading = false;
							}
						} else {
							/* Read into memory
							 */
							session->bytes_in_buffer += bytes_read;
							*(session->request + session->bytes_in_buffer) = '\0';

							if (session->bytes_in_buffer > max_request_size) {
								keep_reading = false;
								session->error_cause = ec_MAX_REQUESTSIZE;
								result = -1;
								break;
							}
						}
				}
		}
	} while (keep_reading);

	if (upload_handle != -1) {
		fsync(upload_handle);
		close(upload_handle);
	}

#ifdef ENABLE_TOMAHAWK
	increment_transfer(TRANSFER_RECEIVED, header_length + content_length);
#endif

	return result;
}

/* Convert the requestbuffer to a session record.
 */
int parse_request(t_session *session, int total_bytes) {
	int retval = 200;
	char *request_end, *str_end, *conn;

	request_end = session->request + total_bytes;

	/* Request method
	 */
	session->method = str_end = session->request;
	while ((*str_end != ' ') && (str_end != request_end)) {
		str_end++;
	}
	if (str_end == request_end) {
		return 400;
	}
	*str_end = '\0';
	session->uri = ++str_end;

	/* URI
	 */
	while ((*str_end != ' ') && (str_end != request_end)) {
		str_end++;
	}
	if (str_end == request_end) {
		return 400;
	}
	*(str_end++) = '\0';
	session->uri_len = strlen(session->uri);
	if ((session->config->max_url_length > 0) && (session->uri_len > session->config->max_url_length)) {
		return 414;
	}

	if (strncmp(session->uri, "http://", 7) == 0) {
		return 400;
	} else if ((session->request_uri = strdup(session->uri)) == NULL) {
		return -1;
	}

	/* Protocol version
	 */
	if (min_strlen(str_end, 10) == false) {
		return 400;
	} else if (memcmp(str_end, "HTTP/", 5) != 0) {
		return 400;
	}

	session->http_version = str_end;
	str_end += 7;

	if ((*(str_end - 1) != '.') || (*(str_end + 1) != '\r') || (*(str_end + 2) != '\n')) {
		return 400;
	} else if (*(str_end - 2) != '1') {
		return 505;
	}
	*(str_end + 1) = '\0';

	/* Body and other request headerlines
	 */
	if ((session->content_length > 0) && (session->uploaded_file == NULL)) {
		session->body = session->request + session->header_length;
	}
	session->http_headers = parse_http_headers(str_end + 3);
	session->hostname = strlower(get_http_header("Host:", session->http_headers));
	session->cookies = get_http_header("Cookie:", session->http_headers);

	if ((conn = get_http_header("Connection:", session->http_headers)) != NULL) {
		conn = strlower(remove_spaces(conn));
	}
	session->keep_alive = false;

	switch (*str_end) {
		case '0':
			if ((conn != NULL) && (session->kept_alive < session->binding->max_keepalive)) {
				if (strcasecmp(conn, "keep-alive") == 0) {
					session->keep_alive = true;
				}
			}
			break;
		case '1':
			if (session->hostname == NULL) {
				retval = 400;
			} else if (session->kept_alive < session->binding->max_keepalive) {
				session->keep_alive = true;
				if (conn != NULL) {
					if (strcmp(conn, "close") == 0) {
						session->keep_alive = false;
					}
				}
			}
			break;
		default:
			retval = 505;
			break;
	}
	if (session->keep_alive) {
		session->kept_alive++;
	}

	session->parsing_oke = true;

	return retval;
}

/* Convert the request uri to a filename.
 */
int uri_to_path(t_session *session) {
	size_t length;
	char *strstart, *strend;
	t_keyvalue *alias;
	int retval;

	/* Requested file in userdirectory?
	 */
	if (session->host->user_websites && (session->uri_len >= 3)) {
		if (*(session->uri + 1) == '~') {
			strstart = session->uri + 1;
			if ((strend = strchr(strstart, '/')) == NULL) {
				return 301;
			} else if ((length = strend - strstart) > 1) {
				if ((session->local_user = (char*)malloc(length + 1)) == NULL) {
					return 500;
				}

				memcpy(session->local_user, strstart, length);
				*(session->local_user + length) = '\0';

				if ((retval = get_homedir(session, session->local_user + 1)) != 200) {
					return retval;
				}
				session->host->error_handlers = NULL;
			} else {
				/* uri is '/~/...' */
				return 404;
			}
		}
	}

	/* Search for a script alias
	 */
	alias = session->host->script_alias;
	while (alias != NULL) {
		if (session->host->enable_path_info) {
			if ((retval = strncmp(session->uri, alias->key, alias->key_len)) == 0) {
				if (strlen(session->uri) > alias->key_len) {
					if (*(session->uri + alias->key_len) != '/') {
						retval = -1;
					}
				}
			}
		} else {
			retval = strcmp(session->uri, alias->key);
		}
		if (retval == 0) {
			if ((session->file_on_disk = strdup(alias->value)) == NULL) {
				return 500;
			}
			session->script_alias = alias;
			return 200;
		}
		alias = alias->next;
	}

	/* Search for an alias.
	 */
	alias = session->host->alias;
	while (alias != NULL) {
		if (strncmp(session->uri, alias->key, alias->key_len) == 0) {
			if ((*(session->uri + alias->key_len) == '/') || (*(session->uri + alias->key_len) == '\0')) {
				session->alias = alias;
				break;
			}
		}
		alias = alias->next;
	}

	/* Allocate memory
	 */
	if (alias == NULL) {
		length = session->host->website_root_len;
	} else {
		length = strlen(alias->value);
	}
	length += session->uri_len + MAX_START_FILE_LENGTH;

	if ((session->file_on_disk = (char*)malloc(length + 4)) == NULL) { /* + 3 for '.gz' (gzip encoding) */
		return 500;
	}

	/* Copy stuff
	 */
	if (alias == NULL) {
		length = session->host->website_root_len;
		memcpy(session->file_on_disk, session->host->website_root, length);
		strstart = session->uri;
		if (session->local_user != NULL) {
			strstart += strlen(session->local_user) + 1;
		}
	} else {
		length = strlen(alias->value);
		memcpy(session->file_on_disk, alias->value, length);
		strstart = session->uri + alias->key_len;

	}
	strcpy(session->file_on_disk + length, strstart);

	return 200;
}

int get_path_info(t_session *session) {
	t_fs_type filetype;
	char *slash;

	if (session->script_alias != NULL) {
		if (strlen(session->uri) > session->script_alias->key_len) {
			if ((session->path_info = strdup(session->uri + session->script_alias->key_len)) == NULL) {
				return 500;
			}
		}

		return 200;
	} else if (session->alias != NULL) {
		if (session->alias->key_len >= strlen(session->file_on_disk)) {
			return 500;
		}

		slash = session->file_on_disk + session->alias->value_len;
	} else {
		if (session->host->website_root_len >= strlen(session->file_on_disk)) {
			return 500;
		}

		slash = session->file_on_disk + session->host->website_root_len + 1;
	}

	while (*slash != '\0') {
		if (*slash == '/') {
			*slash = '\0';
			filetype = file_type(session->file_on_disk);
			*slash = '/';

			switch (filetype) {
				case ft_error:
					return 500;
				case ft_not_found:
					return 404;
				case ft_no_access:
				case ft_other:
					return 403;
				case ft_file:
					if ((session->path_info = strdup(slash)) == NULL) {
						return -1;
					}
					*slash = '\0';
					return 200;
				case ft_dir:
					break;
			}
		}
		slash++;
	}

	return 200;
}

/* Validate URL
 */
bool validate_url(t_session *session) {
	if (valid_uri(session->uri, session->host->allow_dot_files)) {
		if (session->host->secure_url == false) {
			return true;
		} else if (strstr(session->request_uri, "%00") == NULL) {
			return true;
		} else {
			session->return_code = 403;
		}
	} else {
		session->return_code = (session->request_method == PUT) ? 403 : 404;
	}

	log_exploit_attempt(session, "invalid URL", NULL);
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_EXPLOIT);
#endif
#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled) {
		monitor_count_exploit_attempt(session);
		monitor_event("Invalid URL %s for %s", session->uri, session->host->hostname.item[0]);
	}
#endif

	session->error_cause = ec_INVALID_URL;

	return false;
}

/* Return an error message.
 */
const char *http_error(int code) {
	int i;
	static const struct {
		int code;
		const char *message;
	} error[] = {
		/* Informational
		 */
		{100, "Continue"},
		{101, "Switching Protocols"},
		{102, "Processing"},
		{103, "Checkpoint"},

		/* Success
		 */
		{200, "OK"},
		{201, "Created"},
		{202, "Accepted"},
		{203, "Non-Authoritative Information"},
		{204, "No Content"},
		{205, "Reset Content"},
		{206, "Partial Content"},
		{207, "Multi-Status"},
		{208, "Already Reported"},

		/* Redirection
		 */
		{300, "Multiple Choices"},
		{301, "Moved Permanently"},
		{302, "Found"},
		{303, "See Other"},
		{304, "Not Modified"},
		{305, "Use Proxy"},
		{307, "Temporary Redirect"},
		{308, "Resume Incomplete"},

		/* Client error
		 */
		{400, "Bad Request"},
		{401, "Unauthorized"},
		{402, "Payment Required"},
		{403, "Forbidden"},
		{404, "Not Found"},
		{405, "Method Not Allowed"},
		{406, "Not Acceptable"},
		{407, "Proxy Authentication Required"},
		{408, "Request Timeout"},
		{409, "Conflict"},
		{410, "Gone"},
		{411, "Length Required"},
		{412, "Precondition Failed"},
		{413, "Request Entity Too Large"},
		{414, "Request-URI Too Long"},
		{415, "Unsupported Media Type"},
		{416, "Requested Range Not Satisfiable"},
		{417, "Expectation Failed"},
		{418, "I'm a teapot"},
		{422, "Unprocessable Entity"},
		{423, "Locked"},
		{424, "Failed Dependency"},
		{425, "Unordered Collection"},
		{426, "Upgrade Required"},
		{428, "Precondition Required"},
		{429, "Too Many Requests"},
		{431, "Request Header Fields Too Large"},
		{440, "Client TLS Certificate Required"},
		{441, "SQL Injection Detected"},
		{442, "Cross-Site Scripting Detected"},
		{443, "Cross-Site Request Forgery Detected"},
		{444, "Banned Due To Misconduct"},
		{451, "Unavailable For Legal Reasons"},

		/* Server error
		 */
		{500, "Internal Server Error"},
		{501, "Not Implemented"},
		{502, "Bad Gateway"},
		{503, "Service Unavailable"},
		{504, "Gateway Timeout"},
		{505, "HTTP Version Not Supported"},
		{506, "Variant Also Negotiates"},
		{507, "Insufficient Storage"},
		{508, "Loop Detected"},
		{509, "Bandwidth Limit Exceeded"},
		{510, "Not Extended"},
		{511, "Network Authentication Required"},
		{0,   NULL}
	};

	for (i = 0; error[i].code != 0; i++) {
		if (error[i].code == code) {
			return error[i].message;
		}
	}

	return NULL;
}

bool empty_body_because_of_http_status(int status) {
	return ((status >= 100) && (status < 200)) || (status == 204) || (status == 304);
}

int last_forwarded_ip(t_http_header *http_headers, t_ip_addr *ip_addr) {
	char *forwarded, *search, ip_str[MAX_IP_STR_LEN + 1], *begin, *end;
	size_t len;
	int port;

	if ((forwarded = get_http_header(hs_forwarded, http_headers)) != NULL) {
		/* Forwarded header
		 */
		begin = NULL;
		while ((forwarded = strcasestr(forwarded, "for=")) != NULL) {
			begin = forwarded + 4;
			forwarded++;
		}

		if (begin == NULL) {
			return -1;
		}

		end = begin;
		while ((*end != '\0') && (*end != ',') && (*end != ';')) {
			end++;
		}

		if (*begin == '"') {
			begin++;
			end--;
			if (*end != '"') {
				return -1;
			}
		}

		len = end - begin;
		if (len > MAX_IP_STR_LEN) {
			return -1;
		}

		memcpy(ip_str, begin, len);
		*(ip_str + len) = '\0';
		forwarded = ip_str;
	} else if ((forwarded = get_http_header(hs_x_forwarded_for, http_headers)) != NULL) {
		/* X-Forwarded-For header
		 */
		if ((search = strrchr(forwarded, ',')) != NULL) {
			forwarded = search + 1;
			while (*forwarded == ' ') {
				forwarded++;
			}
		}
	} else {
		return -1;
	}

	if (parse_ip(forwarded, ip_addr) == -1) {
		if (parse_ip_port(forwarded, ip_addr, &port) == -1) {
			return -1;
		}
	}

	return 0;
}
