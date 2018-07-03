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
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include "tls.h"
#include "libfs.h"
#include "libstr.h"
#include "liblist.h"
#include "http.h"
#include "log.h"
#include "send.h"
#include "serverconfig.h"
#include "tomahawk.h"
#include "memdbg.h"

#define MAX_TO_BUFFER     1000
#define NONCE_DIGITS        10
#define TIMESTR_SIZE        64
#define FCGI_CHUNK_SIZE    (64 * KILOBYTE - 8)
#define STREAM_BUFFER_SIZE  32 * KILOBYTE

char *hs_http10  = "HTTP/1.0 ";                  /*  9 */
char *hs_http11  = "HTTP/1.1 ";                  /*  9 */
char *hs_server  = "Server: ";                   /*  8 */
char *hs_conn    = "Connection: ";               /* 12 */
char *hs_concl   = "close\r\n";                  /*  7 */
char *hs_conka   = "keep-alive\r\n";             /* 12 */
char *hs_conup   = "upgrade\r\n";                /*  9 */
char *hs_contyp  = "Content-Type: ";             /* 14 */
char *hs_conlen  = "Content-Length: ";           /* 16 */
char *hs_lctn    = "Location: ";                 /* 10 */
char *hs_caco    = "Cache-Control: ";            /* 15 */
char *hs_public  = "public\r\n";                 /*  8 */
char *hs_private = "private\r\n";                /*  9 */
char *hs_expires = "Expires: ";                  /*  9 */
char *hs_http    = "http://";                    /*  7 */
char *hs_https   = "https://";                   /*  8 */
char *hs_hsts    = "Strict-Transport-Security: max-age="; /* 35 */
char *hs_range   = "Accept-Ranges: bytes\r\n";   /* 22 */
char *hs_gzip    = "Content-Encoding: gzip\r\n"; /* 24 */
char *hs_chunked = "Transfer-Encoding: chunked\r\n";  /* 28 */
char *hs_eol     = "\r\n";                       /*  2 */
char *hs_forwarded       = "Forwarded:";         /* 10 */
char *hs_x_forwarded_for = "X-Forwarded-For:";   /* 16 */

char *unknown_http_code = "Unknown Error";

static char *ec_doctype = "<!DOCTYPE html>\n";
static char *ec_head    = "<html>\n<head>\n<title>";
static char *ec_body1   = "</title>\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n<style type=\"text/css\">\n"
                          "body { background-color:#d0d0d0; font-family:sans-serif; padding:0 30px }\n"
                          "div { background-color:#f8f8f8; letter-spacing:4px; max-width:400px; margin:100px auto 0 auto; padding:50px; "
                                "border-radius:10px; border:1px solid #808080; box-shadow:8px 15px 20px #404040 }\n"
                          "h1 { margin:0; font-size:22px; font-weight:normal }\n"
                          "p { margin:10px 0 0 0; padding-top:2px; font-size:14px; color:#606060; border-top:1px solid #a0a0ff; "
                              "text-align:right; font-weight:bold }\n"
                          "@media (max-width:767px) { h1 { font-size:90%; letter-spacing:2px } p { font-size:70% } }\n"
                          "</style>\n</head>\n<body>\n<div>\n<h1>";
static char *ec_body2   = "</h1>\n<p>";
static char *ec_tail    = "</p>\n</div>\n</body>\n</html>";
static int ec_doctype_len, ec_head_len, ec_body1_len, ec_body2_len, ec_tail_len;

void init_send_module(void) {
	ec_doctype_len = strlen(ec_doctype);
	ec_head_len    = strlen(ec_head);
	ec_body1_len   = strlen(ec_body1);
	ec_body2_len   = strlen(ec_body2);
	ec_tail_len    = strlen(ec_tail);
}

/* Send a char buffer to the client. Traffic throttling is handled here.
 */
static int send_to_client(t_session *session, const char *buffer, int size) {
	int bytes_sent = 0, total_sent = 0, can_send, rest;
	time_t new_time;

	/* Send buffer to browser.
	 */
	if (session->socket_open == false) {
		return -1;
	} else if ((buffer == NULL) || (size <= 0)) {
		return 0;
	}

	if (session->directory != NULL) {
		if (session->directory->session_speed > 0) {
			session->throttle = session->directory->session_speed;
		}
	}

	do {
		rest = size - total_sent;
		if (session->throttle > 0) {
			do {
				new_time = time(NULL);
				if (session->throttle_timer < new_time) {
					session->bytecounter = 0;
					session->throttle_timer = new_time;
				}
				can_send = session->throttle - session->bytecounter;
				if (can_send <= 0) {
					usleep(10000);
				}
			} while (can_send <= 0);
			if (can_send > rest) {
				can_send = rest;
			}
		} else {
			can_send = rest;
		}

#ifdef ENABLE_TLS
		if (session->binding->use_tls) {
			if ((bytes_sent = tls_send(&(session->tls_context), (char*)(buffer + total_sent), can_send)) <= 0) {
				bytes_sent = -1;
			}
		} else
#endif
			if ((bytes_sent = send(session->client_socket, (char*)(buffer + total_sent), can_send, 0)) <= 0) {
				bytes_sent = -1;
			}

		/* Handle read result
		 */
		if (bytes_sent == -1) {
			if (errno != EINTR) {
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
					if (session->config->log_timeouts) {
						log_error_session(session, "send timeout");
					}
				} else if ((errno != EPIPE) && (errno != ECONNRESET)) {
					log_error_session(session, "error while sending response");
				}
				close_socket(session);
				session->keep_alive = false;
				session->error_cause = ec_SOCKET_WRITE_ERROR;
				return -1;
			}
		} else {
			total_sent += bytes_sent;
			session->bytecounter += bytes_sent;
		}
	} while (total_sent < size);
#ifdef ENABLE_TOMAHAWK
	increment_transfer(TRANSFER_SEND, total_sent);
#endif

	return 0;
}

/* This function has been added to improve speed by buffering small amounts of data to be sent.
 */
int send_buffer(t_session *session, const char *buffer, int size) {
	if (size > MAX_TO_BUFFER) {
		if (session->output_size > 0) {
			if (send_to_client(session, session->output_buffer, session->output_size) == -1) {
				return -1;
			}
			session->output_size = 0;
		}
		if (send_to_client(session, buffer, size) == -1) {
			return -1;
		}
	} else if (buffer == NULL) {
		if (session->output_size > 0) {
			if (send_to_client(session, session->output_buffer, session->output_size) == -1) {
				return -1;
			}
			session->output_size = 0;
		}
	} else {
		if ((session->output_size + size > OUTPUT_BUFFER_SIZE) && (session->output_size > 0)) {
			if (send_to_client(session, session->output_buffer, session->output_size) == -1) {
				return -1;
			}
			session->output_size = 0;
		}

		memcpy(session->output_buffer + session->output_size, buffer, size);
		session->output_size += size;
	}

	session->bytes_sent += size;

	return 0;
}

/* Send a HTTP header to the client. Header is not closed by this function.
 */
int send_header(t_session *session) {
#ifdef ENABLE_TLS
	char random_header[MAX_RANDOM_HEADER_LENGTH + 13];
	char *rand_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789PR";
	unsigned long length, i;
	int random;
#endif
	char ecode[5], timestr[TIMESTR_SIZE];
	const char *emesg;
	time_t t;
	struct tm s;
	t_keyvalue *header;

	/* Send HTTP header.
	 */
	ecode[4] = '\0';
	snprintf(ecode, 4, "%d", session->return_code);
	if ((emesg = http_error(session->return_code)) == NULL) {
		emesg = unknown_http_code;
	}

	session->data_sent = true;

	/* HTTP version
	 */
	if (session->http_version != NULL) {
		if (*(session->http_version + 7) == '0') {
			if (send_buffer(session, hs_http10, 9) == -1) {
				return -1;
			}
		} else {
			if (send_buffer(session, hs_http11, 9) == -1) {
				return -1;
			}
		}
	} else {
		if (send_buffer(session, hs_http11, 9) == -1) {
			return -1;
		}
	}

	/* HTTP code
	 */
	if (send_buffer(session, ecode, 3) == -1) {
		return -1;
	} else if (send_buffer(session, " ", 1) == -1) {
		return -1;
	} else if (send_buffer(session, emesg, strlen(emesg)) == -1) {
		return -1;
	} else if (send_buffer(session, hs_eol, 2) == -1) {
		return -1;
	}

	/* Date
	 */
	if (session->send_date) {
		if (time(&t) == -1) {
			return -1;
		} else if (gmtime_r(&t, &s) == NULL) {
			return -1;
		} else if (strftime(timestr, TIMESTR_SIZE, "%a, %d %b %Y %X GMT\r\n", &s) == 0) {
			return -1;
		} else if (send_buffer(session, "Date: ", 6) == -1) {
			return -1;
		} else if (send_buffer(session, timestr, strlen(timestr)) == -1) {
			return -1;
		}
	}

	/* Server
	 */
	if (session->config->server_string != NULL) {
		if (send_buffer(session, hs_server, 8) == -1) {
			return -1;
		} else if (send_buffer(session, session->config->server_string, strlen(session->config->server_string)) == -1) {
			return -1;
		} else if (send_buffer(session, hs_eol, 2) == -1) {
			return -1;
		}
	}

	/* Range
	 */
	if ((session->cgi_type == no_cgi) && (session->uri_is_dir == false)) {
		if (send_buffer(session, hs_range, 22) == -1) {
			return -1;
		}
	}

	/* Connection
	 */
	if (send_buffer(session, hs_conn, 12) == -1) {
		return -1;
	} else if (session->keep_alive) {
		if (send_buffer(session, hs_conka, 12) == -1) {
			return -1;
		}
	} else if (send_buffer(session, hs_concl, 7) == -1) {
		return -1;
	}

	/* Content-Encoding
	 */
	if (session->encode_gzip) {
		if (send_buffer(session, hs_gzip, 24) == -1) {
			return -1;
		}
	}

	/* Content-Type
	 */
	if (session->mimetype != NULL) {
		if (send_buffer(session, hs_contyp, 14) == -1) {
			return -1;
		} else if (send_buffer(session, session->mimetype, strlen(session->mimetype)) == -1) {
			return -1;
		} else if (send_buffer(session, "\r\n", 2) == -1) {
			return -1;
		}
	}

	/* Expires
	 */
	if (session->send_expires && (session->expires > -1) && (session->return_code == 200)) {
		if (time(&t) == -1) {
			return -1;
		}
		t += (time_t)session->expires;

		if (gmtime_r(&t, &s) == NULL) {
			return -1;
		} else if (send_buffer(session, hs_caco, 15) == -1) {
			return -1;
		}

		if (session->caco_private) {
			if (send_buffer(session, hs_private, 9) == -1) {
				return -1;
			}
		} else {
			if (send_buffer(session, hs_public, 8) == -1) {
				return -1;
			}
		}

		if (send_buffer(session, hs_expires, 9) == -1) {
			return -1;
		} else if (strftime(timestr, TIMESTR_SIZE, "%a, %d %b %Y %X GMT\r\n", &s) == 0) {
			return -1;
		} else if (send_buffer(session, timestr, strlen(timestr)) == -1) {
			return -1;
		}
	}

	/* Custom headers
	 */
	header = session->host->custom_headers_client;
	while (header != NULL) {
		if (send_buffer(session, header->key, strlen(header->key)) == -1) {
			return -1;
		} else if (send_buffer(session, ": ", 2) == -1) {
			return -1;
		} else if (send_buffer(session, header->value, strlen(header->value)) == -1) {
			return -1;
		} else if (send_buffer(session, "\r\n", 2) == -1) {
			return -1;
		}

		header = header->next;
	}

#ifdef ENABLE_TLS
	/* Random header
	 */
	if ((session->host->random_header_length > -1) && session->binding->use_tls) {
		sprintf(random_header, "X-Random: ");
		length = (session->host->random_header_length * ((unsigned int)rand() & MAX_RANDOM_HEADER_LENGTH_MASK)) / MAX_RANDOM_HEADER_LENGTH_MASK;
		if (length == 0) {
			length = 1;
		}
		sprintf(random_header + 10 + length, "\r\n");

		random = rand() & 63;
		for (i = 0; i < length; i++) {
			random_header[10 + i] = rand_set[random];
		}

		if (send_buffer(session, random_header, 12 + length) == -1) {
			return -1;
		}
	}

	/* HTTP Strict Transport Security
	 */
	if ((session->host->hsts_time != NULL) && session->binding->use_tls) {
		if (send_buffer(session, hs_hsts, 35) == -1) {
			return -1;
		}
		if (send_buffer(session, session->host->hsts_time, strlen(session->host->hsts_time)) == -1) {
			return -1;
		}
		if (send_buffer(session, "\r\n", 2) == -1) {
			return -1;
		}
	}

	/* HTTP Public Key Pinning
	 */
	if (session->binding->use_tls && (session->host->hpkp_data != NULL)) {
		if (session->host->hpkp_data->http_header != NULL) {
			send_buffer(session, session->host->hpkp_data->http_header, session->host->hpkp_data->header_size);
		}
	}
#endif

	return 0;
}

/* Send a datachunk to the client without buffering
 */
static int send_chunk_to_client(t_session *session, const char *chunk, int size) {
	char hex[10];

	if (session->keep_alive) {
		hex[9] = '\0';
		if (snprintf(hex, 9, "%x\r\n", size) < 0) {
			return -1;
		} else if (send_to_client(session, hex, strlen(hex)) == -1) {
			return -1;
		}
	}

	if (send_to_client(session, chunk, size) == -1) {
		return -1;
	}

	if (session->keep_alive) {
		if (send_to_client(session, "\r\n", 2) == -1) {
			return -1;
		}
	}

	return 0;
}

int send_chunk(t_session *session, const char *chunk, int size) {
	if (size > MAX_TO_BUFFER) {
		if (session->output_size > 0) {
			if (send_chunk_to_client(session, session->output_buffer, session->output_size) == -1) {
				return -1;
			}
			session->output_size = 0;
		}
		if (send_chunk_to_client(session, chunk, size) == -1) {
			return -1;
		}
	} else if (chunk == NULL) {
		if (session->output_size > 0) {
			if (send_chunk_to_client(session, session->output_buffer, session->output_size) == -1) {
				return -1;
			}
			session->output_size = 0;
		}

		if (size == 0) {
			if (send_to_client(session, "0\r\n\r\n", 5) == -1) {
				return -1;
			}
		}
	} else {
		if ((session->output_size + size > OUTPUT_BUFFER_SIZE) && (session->output_size > 0)) {
			if (send_chunk_to_client(session, session->output_buffer, session->output_size) == -1) {
				return -1;
			}
			session->output_size = 0;
		}

		memcpy(session->output_buffer + session->output_size, chunk, size);
		session->output_size += size;
	}

	session->bytes_sent += size;

	return 0;
}

/* Send header of HTTP error message.
 */
int send_http_code_header(t_session *session) {
	if (session->return_code == -1) {
		session->return_code = 500;
	}

	session->mimetype = NULL;
	if (send_header(session) == -1) {
		return -1;
	}

	switch (session->return_code) {
		case 301:
		case 302:
		case 303:
		case 304:
		case 305:
		case 306:
		case 307:
		case 308:
			if (send_buffer(session, hs_lctn, 10) == -1) {
				return -1;
			}

			if (session->cause_of_30x == enforce_first_hostname) {
#ifdef ENABLE_TLS
				if (session->binding->use_tls || session->host->require_tls) {
					if (send_buffer(session, hs_https, 8) == -1) {
						return -1;
					}
				} else
#endif
				if (send_buffer(session, hs_http, 7) == -1) {
					return -1;
				}

				if (send_buffer(session, *(session->host->hostname.item), strlen(*(session->host->hostname.item))) == -1) {
					return -1;
				}
			}

			if (session->cause_of_30x == location) {
				if (session->location != NULL) {
					if (send_buffer(session, session->location, strlen(session->location)) == -1) {
						return -1;
					}
				}
				if (send_buffer(session, "\r\n", 2) == -1) {
					return -1;
				}
				break;
			}

#ifdef ENABLE_TLS
			if (session->cause_of_30x == require_tls) {
				if (send_buffer(session, hs_https, 8) == -1) {
					return -1;
				}

				if (session->hostname != NULL) {
					if (send_buffer(session, session->hostname, strlen(session->hostname)) == -1) {
						return -1;
					}
				} else if (send_buffer(session, *(session->host->hostname.item), strlen(*(session->host->hostname.item))) == -1) {
					return -1;
				}
			}
#endif

			if (send_buffer(session, session->uri, session->uri_len) == -1) {
				return -1;
			}

			if (session->cause_of_30x == missing_slash) {
				if (send_buffer(session, "/", 1) == -1) {
					return -1;
				}
			}
			if (session->vars != NULL) {
				if (send_buffer(session, "?", 1) == -1) {
					return -1;
				} else if (send_buffer(session, session->vars, strlen(session->vars)) == -1) {
					return -1;
				}
			}
			if (send_buffer(session, "\r\n", 2) == -1) {
				return -1;
			}
			break;
		case 401:
			if (session->host->auth_method == basic) {
				if (send_basic_auth(session) == -1) {
					return -1;
				}
			} else {
				if (send_digest_auth(session) == -1) {
					return -1;
				}
			}
			break;
	}

	return 0;
}

/* Send body of HTTP error message
 */
int send_http_code_body(t_session *session) {
	char ecode[5], len[10];
	const char *emesg;
	size_t ecode_len, emesg_len;

	ecode[4] = '\0';
	snprintf(ecode, 4, "%d", session->return_code);
	ecode_len = strlen(ecode);

	if ((emesg = http_error(session->return_code)) == NULL) {
		emesg = unknown_http_code;
	}
	emesg_len = strlen(emesg);
	len[9] = '\0';
	snprintf(len, 9, "%d", (int)((2 * emesg_len) + (2 * ecode_len) + 3 + ec_doctype_len + ec_head_len + ec_body1_len + ec_body2_len + ec_tail_len));

	if (send_buffer(session, hs_conlen, 16) == -1) {
		return -1;
	} else if (send_buffer(session, len, strlen(len)) == -1) {
		return -1;
	} else if (send_buffer(session, "\r\n", 2) == -1) {
		return -1;
	} else if (send_buffer(session, hs_contyp, 14) == -1) {
		return -1;
	} else if (send_buffer(session, "text/html\r\n\r\n", 13) == -1) {
		return -1;
	}
	session->header_sent = true;

	if (session->request_method == HEAD) {
		return 0;
	}

	if (send_buffer(session, ec_doctype, ec_doctype_len) == -1) {
		return -1;
	} else if (send_buffer(session, ec_head, ec_head_len) == -1) {
		return -1;
	} else if (send_buffer(session, ecode, ecode_len) == -1) {
		return -1;
	} else if (send_buffer(session, " - ", 3) == -1) {
		return -1;
	} else if (send_buffer(session, emesg, emesg_len) == -1) {
		return -1;
	} else if (send_buffer(session,	ec_body1, ec_body1_len) == -1) {
		return -1;
	} else if (send_buffer(session, emesg, emesg_len) == -1) {
		return -1;
	} else if (send_buffer(session,	ec_body2, ec_body2_len) == -1) {
		return -1;
	} else if (send_buffer(session, ecode, ecode_len) == -1) {
		return -1;
	} else if (send_buffer(session, ec_tail, ec_tail_len) == -1) {
		return -1;
	}

	return 0;
}

static void fcgi_set_padding(t_fcgi_buffer *fcgi_buffer) {
	unsigned char padding;

	if ((padding = fcgi_buffer->data[5] & 7) > 0) {
		padding = 8 - padding;
		memset(fcgi_buffer->data + fcgi_buffer->size, 0, (size_t)padding);
		fcgi_buffer->size += (long)padding;
	}
	fcgi_buffer->data[6] = padding;
}

int send_fcgi_buffer(t_fcgi_buffer *fcgi_buffer, const char *buffer, long size) {
	long written;

	if (size > FCGI_BUFFER_SIZE) {
		if (fcgi_buffer->size > 0) {
			fcgi_set_padding(fcgi_buffer);
			if (write_buffer(fcgi_buffer->sock, (char*)fcgi_buffer->data, fcgi_buffer->size) == -1) {
				return -1;
			}

			fcgi_buffer->size = 0;
		}

		memcpy(fcgi_buffer->data, "\x01\x00\x00\x01" "\xff\xff\x00\x00", 8);
		fcgi_buffer->data[1] = fcgi_buffer->type;
		fcgi_buffer->data[4] = (FCGI_CHUNK_SIZE >> 8) & 255;
		fcgi_buffer->data[5] = FCGI_CHUNK_SIZE & 255;

		written = 0;
		do {
			if (write_buffer(fcgi_buffer->sock, (char*)fcgi_buffer->data, 8) == -1) {
				return -1;
			} else if (write_buffer(fcgi_buffer->sock, buffer + written, FCGI_CHUNK_SIZE) == -1) {
				return -1;
			}
			written += FCGI_CHUNK_SIZE;
		} while (size - written > FCGI_BUFFER_SIZE);

		if (send_fcgi_buffer(fcgi_buffer, buffer + written, size - written) == -1) {
			return -1;
		}
	} else if (buffer == NULL) {
		if (fcgi_buffer->size > 0) {
			fcgi_set_padding(fcgi_buffer);
			if (write_buffer(fcgi_buffer->sock, (char*)fcgi_buffer->data, fcgi_buffer->size) == -1) {
				return -1;
			}
		}

		memcpy(fcgi_buffer->data, "\x01\x00\x00\x01" "\x00\x00\x00\x00", 8);
		fcgi_buffer->data[1] = fcgi_buffer->type;
		if (write_buffer(fcgi_buffer->sock, (char*)fcgi_buffer->data, 8) == -1) {
			return -1;
		}

		fcgi_buffer->size = 0;
	} else {
		if ((fcgi_buffer->size + size > FCGI_BUFFER_SIZE) && (fcgi_buffer->size > 0)) {
			fcgi_set_padding(fcgi_buffer);
			if (write_buffer(fcgi_buffer->sock, (char*)fcgi_buffer->data, fcgi_buffer->size) == -1) {
				return -1;
			}
			fcgi_buffer->size = 0;
		}

		if (fcgi_buffer->size == 0) {
			memcpy(fcgi_buffer->data, "\x01\x00\x00\x01" "\x00\x00\x00\x00", 8);
			fcgi_buffer->data[1] = fcgi_buffer->type;
			fcgi_buffer->size = 8;
		}

		memcpy(fcgi_buffer->data + fcgi_buffer->size, buffer, size);
		fcgi_buffer->size += size;
		fcgi_buffer->data[4] = ((fcgi_buffer->size - 8) >> 8) & 255;
		fcgi_buffer->data[5] = (fcgi_buffer->size - 8) & 255;
	}

	return 0;
}

/* Send a Basic Authentication message to the client.
 */
int send_basic_auth(t_session *session) {
	if (send_buffer(session, "WWW-Authenticate: Basic", 23) == -1) {
		return -1;
	} else if (session->host->login_message != NULL) {
		if (send_buffer(session, " realm=\"", 8) == -1) {
			return -1;
		} else if (send_buffer(session, session->host->login_message, strlen(session->host->login_message)) == -1) {
			return -1;
		} else if (send_buffer(session, "\"", 1) == -1) {
			return -1;
		}
	}

	return send_buffer(session, "\r\n", 2);
}

/* Send a Digest Authentication message to the client.
 */
int send_digest_auth(t_session *session) {
	char nonce[2 * NONCE_DIGITS + 1];
	int i;

	for (i = 0; i < NONCE_DIGITS; i++) {
		snprintf(nonce + (2 * i), 3, "%02hhX", (char)random());
	}

	if (send_buffer(session, "WWW-Authenticate: Digest", 24) == -1) {
		return -1;
	} else if (session->host->login_message != NULL) {
		if (send_buffer(session, " realm=\"", 8) == -1) {
			return -1;
		} else if (send_buffer(session, session->host->login_message, strlen(session->host->login_message)) == -1) {
			return -1;
		} else if (send_buffer(session, "\"", 1) == -1) {
			return -1;
		}
	}

	if (send_buffer(session, ", nonce=\"", 9) == -1) {
		return -1;
	} else if (send_buffer(session, nonce, 2 * NONCE_DIGITS) == -1) {
		return -1;
	}

	return send_buffer(session, "\", algorithm=MD5\r\n", 18);
}

/* Link two streams
 */
int link_streams(t_stream *stream1, t_stream *stream2, int poll_timeout) {
	struct pollfd poll_data[2];
	int result, poll_result, bytes_read;
	bool keep_reading;
	char buffer[STREAM_BUFFER_SIZE];

	poll_data[0].fd = stream1->socket;
	poll_data[0].events = POLL_EVENT_BITS;
	poll_data[1].fd = stream2->socket;
	poll_data[1].events = POLL_EVENT_BITS;

	result = 0;
	keep_reading = true;
	poll_timeout *= 1000;

	/* Forward data
	 */
	do {
#ifdef ENABLE_TLS
		poll_result = stream1->use_tls ? tls_pending(stream1->tls_context) : 0;
		if (poll_result == 0) {
			poll_result = stream2->use_tls ? tls_pending(stream2->tls_context) : 0;
		}

		if (poll_result == 0)
#endif
			poll_result = poll(poll_data, 2, poll_timeout);

		switch (poll_result) {
			case -1:
				result = -1;
				keep_reading = false;
				break;
			case 0:
				result = 504;
				keep_reading = false;
				break;
			default:
				/* Data from stream1 to stream2
				 */
				if (poll_data[0].revents != 0) {
#ifdef ENABLE_TLS
					if (stream1->use_tls) {
						if ((bytes_read = tls_receive(stream1->tls_context, buffer, STREAM_BUFFER_SIZE)) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}
					} else
#endif
						if ((bytes_read = read(stream1->socket, buffer, STREAM_BUFFER_SIZE)) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}

					if (bytes_read == 0) {
						keep_reading = false;
						break;
					}

#ifdef ENABLE_TLS
					if (stream2->use_tls) {
						if (tls_send_buffer(stream2->tls_context, buffer, bytes_read) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}
					} else
#endif
						if (write_buffer(stream2->socket, buffer, bytes_read) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}
				}

				/* Data from stream2 to stream1
				 */
				if (poll_data[1].revents != 0) {
#ifdef ENABLE_TLS
					if (stream2->use_tls) {
						if ((bytes_read = tls_receive(stream2->tls_context, buffer, STREAM_BUFFER_SIZE)) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}
					} else
#endif
						if ((bytes_read = read(stream2->socket, buffer, STREAM_BUFFER_SIZE)) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}

					if (bytes_read == 0) {
						keep_reading = false;
						break;
					}

#ifdef ENABLE_TLS
					if (stream1->use_tls) {
						if (tls_send_buffer(stream1->tls_context, buffer, bytes_read) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}
					} else
#endif
						if (write_buffer(stream1->socket, buffer, bytes_read) == -1) {
							keep_reading = false;
							result = -1;
							break;
						}
				}
		}
	} while (keep_reading);

	return result;
}
