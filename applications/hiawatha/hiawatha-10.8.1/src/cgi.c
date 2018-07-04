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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "global.h"
#include "alternative.h"
#include "libstr.h"
#include "send.h"
#include "cgi.h"
#include "client.h"
#include "serverconfig.h"
#include "envir.h"
#include "ip.h"
#include "log.h"
#include "memdbg.h"

#define MAX_CGI_DELAY_TIMER (int)MINUTE / TASK_RUNNER_INTERVAL
#define DUMMY_BUFFER_SIZE           64 * KILOBYTE
#define UPLOADED_FILE_BUFFER_SIZE 4096

static int delay_timer = 0;

int fix_crappy_cgi_headers(t_cgi_info *cgi_info) {
	char *header_end, *new_buffer, *src, *dst;
	int count = 0, header_len, new_size;

	if ((header_end = strstr(cgi_info->input_buffer, "\n\n")) == NULL) {
		return 1;
	}
	header_end += 2;

	/* Count EOL
	 */
	src = cgi_info->input_buffer;
	while (src < header_end) {
		if (*src == '\n') {
			count++;
		}
		src++;
	}

	/* Allocate new buffer
	 */
	new_size = cgi_info->input_len + count;
	if ((new_buffer = (char*)malloc(new_size + 1)) == NULL) {
		return -1;
	}

	/* Fix EOL
	 */
	src = cgi_info->input_buffer;
	dst = new_buffer;
	while (src < header_end) {
		if (*src == '\n') {
			*(dst++) = '\r';
		}
		*(dst++) = *(src++);
	}

	/* Copy request body
	 */
	header_len = header_end - cgi_info->input_buffer;
	memcpy(new_buffer + header_len + count, header_end, cgi_info->input_len - header_len + 1);

	free(cgi_info->input_buffer);
	cgi_info->input_buffer = new_buffer;
	cgi_info->input_len += count;
	cgi_info->input_buffer_size = new_size;

	return 0;
}

char *find_cgi_header(char *buffer, int size, char *header) {
	char *start, *pos;

	if ((header == NULL) || (buffer == NULL)) {
		return NULL;
	}

	start = buffer;
	while ((pos = strncasestr(buffer, header, size)) != NULL) {
		if (pos == start) {
			return start;
		} else if (*(pos - 1) == '\n') {
			return pos;
		}

		size -= pos + 1 - buffer;
		buffer = pos + 1;
	}

	return NULL;
}

/*
 * Load balancer
 * ==============
 */
int init_load_balancer(t_fcgi_server *fcgi_server) {
	int i;

	while (fcgi_server != NULL) {
		for (i = 0; i < 256; i++) {
			fcgi_server->cgi_session_list[i] = NULL;
			if (pthread_mutex_init(&fcgi_server->cgi_session_mutex[i], NULL) != 0) {
				return -1;
			}
		}
		fcgi_server = fcgi_server->next;
	}

	return 0;
}

t_connect_to *select_connect_to(t_fcgi_server *fcgi_server, t_ip_addr *client_ip) {
	t_connect_to  *connect_to = NULL;
	t_cgi_session *cgi_session;
	bool search_new_fcgi_server = true;
	unsigned char i;
	time_t now;


	if ((fcgi_server == NULL) || (client_ip == NULL)) {
		return NULL;
	}

	/* Only one connect_to?
	 */
	if (fcgi_server->connect_to->next == fcgi_server->connect_to) {
		return fcgi_server->connect_to;
	}

	now = time(NULL);

	i = index_by_ip(client_ip);
	pthread_mutex_lock(&fcgi_server->cgi_session_mutex[i]);

	/* Search in cgi_session_list
	 */
	cgi_session = fcgi_server->cgi_session_list[i];
	while (cgi_session != NULL) {
		if (same_ip(&(cgi_session->client_ip), client_ip)) {
			if (now < cgi_session->session_timeout) {
				if (cgi_session->connect_to->available) {
					cgi_session->session_timeout = now + fcgi_server->session_timeout;
					connect_to = cgi_session->connect_to;
				} else {
					/* Make sure it won't match the next round */
					cgi_session->client_ip.family = AF_UNSPEC;
				}
				search_new_fcgi_server = false;
			}
			break;
		}
		cgi_session = cgi_session->next;
	}

	if (search_new_fcgi_server) {
		connect_to = fcgi_server->connect_to;
		while (connect_to->available == false) {
			if ((connect_to = connect_to->next) == fcgi_server->connect_to) {
				break;
			}
		}
		fcgi_server->connect_to = connect_to->next;

		/* Add to cgi_session_list
		 */
		if (fcgi_server->session_timeout > 0) {
			if ((cgi_session = (t_cgi_session*)malloc(sizeof(t_cgi_session))) != NULL) {
				copy_ip(&(cgi_session->client_ip), client_ip);
				cgi_session->connect_to = connect_to;
				cgi_session->session_timeout = now + fcgi_server->session_timeout;

				cgi_session->next = fcgi_server->cgi_session_list[i];
				fcgi_server->cgi_session_list[i] = cgi_session;
			}
		}
	}

	pthread_mutex_unlock(&fcgi_server->cgi_session_mutex[i]);

	return connect_to;
}

void manage_load_balancer(t_config *config, time_t now) {
	t_fcgi_server *fcgi_server;
	t_cgi_session *cgi_session, *last, *next = NULL;
	t_connect_to  *connect_to = NULL;
	int i, sock;

	if (++delay_timer < MAX_CGI_DELAY_TIMER) {
		return;
	}

	fcgi_server = config->fcgi_server;
	while (fcgi_server != NULL) {
		/* Check session timeouts
		 */
		for (i = 0; i < 256; i++) {
			pthread_mutex_lock(&fcgi_server->cgi_session_mutex[i]);

			last = NULL;
			cgi_session = fcgi_server->cgi_session_list[i];
			while (cgi_session != NULL) {
				next = cgi_session->next;

				if ((now > cgi_session->session_timeout) || (cgi_session->connect_to->available == false)) {
					if (last == NULL) {
						fcgi_server->cgi_session_list[i] = next;
					} else {
						last->next = next;
					}
					free(cgi_session);
				} else {
					last = cgi_session;
				}
				cgi_session = next;
			}

			pthread_mutex_unlock(&fcgi_server->cgi_session_mutex[i]);
		}

		/* Check if offline FastCGI servers are available again
		 */
		connect_to = fcgi_server->connect_to;
		do {
			if (connect_to->available == false) {
				if ((sock = connect_to_fcgi_server(connect_to)) != -1) {
					close(sock);
					connect_to->available = true;
				} else {
					log_system(config, "FastCGI server %s is still (partially) unavailable", fcgi_server->fcgi_id);
				}
			}
			connect_to = connect_to->next;
		} while (connect_to != fcgi_server->connect_to);

		fcgi_server = fcgi_server->next;
	}

	delay_timer = 0;
}

/*
 * Search FastCGI server
 * ======================
 */

t_fcgi_server *fcgi_server_match(t_fcgi_server **fcgi_server, char *extension) {
	int i;

	if ((fcgi_server == NULL) || (extension == NULL)) {
		return NULL;
	}

	i = 0;
	while (fcgi_server[i] != NULL) {
		if (fcgi_server[i]->extension.size == 0) {
			return fcgi_server[i];
		} else if (in_charlist(extension, &(fcgi_server[i]->extension))) {
			return fcgi_server[i];
		}

		i++;
	}

	return NULL;
}

t_fcgi_server *find_fcgi_server(t_fcgi_server *fcgi_server, char *fcgi_id) {
	if (fcgi_id == NULL) {
		return NULL;
	}

	while (fcgi_server != NULL) {
		if (strcasecmp(fcgi_server->fcgi_id, fcgi_id) == 0) {
			return fcgi_server;
		}

		fcgi_server = fcgi_server->next;
	}

	return NULL;
}

/*
 * Normal CGI processes
 * =====================
 */

pid_t fork_cgi_process(t_session *session, t_cgi_info *cgi_info) {
	int post_pipe[2], html_pipe[2], error_pipe[2], i, handle, bytes_read;
	char *pos, slash = '/', *run[10], cgi_time[16], buffer[UPLOADED_FILE_BUFFER_SIZE];
	pid_t cgi_pid;

	if (pipe(post_pipe) == -1) {
		return -1;
	} else if (pipe(html_pipe) == -1) {
		close(post_pipe[0]);
		close(post_pipe[1]);
		return -1;
	} else if (pipe(error_pipe) == -1) {
		close(html_pipe[0]);
		close(html_pipe[1]);
		close(post_pipe[0]);
		close(post_pipe[1]);
		return -1;
	}

	switch (cgi_pid = fork()) {
		case -1:
			break;
		case 0:
			/* Child. Executes CGI program.
			 */
			dup2(post_pipe[0], STDIN_FILENO);
			dup2(html_pipe[1], STDOUT_FILENO);
			dup2(error_pipe[1], STDERR_FILENO);

			close(post_pipe[0]);
			close(post_pipe[1]);
			close(html_pipe[0]);
			close(html_pipe[1]);
			close(error_pipe[0]);
			close(error_pipe[1]);

			fcntl(STDIN_FILENO, F_SETFD, 0);
			fcntl(STDOUT_FILENO, F_SETFD, 0);
			fcntl(STDERR_FILENO, F_SETFD, 0);

			/* Close all other open filedescriptors.
			 */
			close_bindings(session->config->binding);
			close_client_sockets_for_cgi_run();
			close_logfiles_for_cgi_run(session->config->first_host);

			set_environment(session, NULL);

			pos = strrchr(session->file_on_disk, slash);
#ifdef CYGWIN
			if ((pos == NULL) && (session->config->platform == windows)) {
				slash = '\\';
				pos = strrchr(session->file_on_disk, slash);
			}
#endif
			if (pos != NULL) {
				*pos = '\0';
				if (chdir(session->file_on_disk) == -1) {
					log_error_file(session, session->file_on_disk, "couldn't change to CGI directory");
				}
				*pos = slash;
			}

			i = 0;
			if (cgi_info->wrap_cgi) {
				run[i++] = session->config->cgi_wrapper;
				if (session->host->wrap_cgi != NULL) {
					setenv("CGIWRAP_ID", session->host->wrap_cgi, 1);
				} else {
					setenv("CGIWRAP_ID", session->local_user, 1);
				}
				if (session->host->follow_symlinks) {
					setenv("CGIWRAP_FOLLOWSYMLINKS", "true", 1);
				} else {
					setenv("CGIWRAP_FOLLOWSYMLINKS", "false", 1);
				}
				cgi_time[15] = '\0';
				snprintf(cgi_time, 15, "%d", session->host->time_for_cgi);
				setenv("CGIWRAP_TIMEFORCGI", cgi_time, 1);
				if (session->config->user_directory_set) {
					setenv("CGIWRAP_USERDIRECTORY", session->config->user_directory, 1);
				}
			} else if (setsid() == -1) {
				exit(EXIT_FAILURE);
			}
			if (session->cgi_handler != NULL) {
				run[i++] = session->cgi_handler;
				run[i++] = session->cgi_handler;
			} else {
				if (cgi_info->wrap_cgi) {
					run[i++] = "-";
				}
				run[i++] = session->file_on_disk;
			}
			run[i++] = session->file_on_disk;
			run[i] = NULL;

			execvp(run[0], run + 1);
			perror("execute CGI");
			exit(EXIT_FAILURE);
		default:
			/* Parent. Reads CGI output.
			 */
			close(post_pipe[0]);
			close(error_pipe[1]);
			close(html_pipe[1]);

			cgi_info->to_cgi = post_pipe[1];
			cgi_info->from_cgi = html_pipe[0];
			cgi_info->cgi_error = error_pipe[0];

			if (session->body != NULL) {
				/* Send POST data to CGI program.
				 */
				if (write_buffer(cgi_info->to_cgi, session->body, session->content_length) == -1) {
					close(cgi_info->to_cgi);
					close(cgi_info->from_cgi);
					close(cgi_info->cgi_error);
					return -1;
				}
			} else if (session->uploaded_file != NULL) {
				/* Send uploaded file to CGI program.
				 */
				if ((handle = open(session->uploaded_file, O_RDONLY)) == -1) {
					bytes_read = -1;
				} else {
					while ((bytes_read = read(handle, buffer, UPLOADED_FILE_BUFFER_SIZE)) > 0) {
						if (write_buffer(cgi_info->to_cgi, buffer, bytes_read) == -1) {
							bytes_read = -1;
							break;
						}
					}
					close(handle);
				}

				if (bytes_read == -1) {
					close(cgi_info->to_cgi);
					close(cgi_info->from_cgi);
					close(cgi_info->cgi_error);
					return -1;
				}
			}
	}

	return cgi_pid;
}

t_cgi_result read_from_cgi_process(t_session *session, t_cgi_info *cgi_info) {
	int bytes_read, result = cgi_OKE;
	bool read_again;
	struct pollfd poll_data[2];
	int poll_size;
	size_t can_read;

	poll_size = 0;
	if (cgi_info->from_cgi != -1) {
		poll_data[poll_size].fd = cgi_info->from_cgi;
		poll_data[poll_size].events = POLL_EVENT_BITS;
		poll_size++;
	}
	if (cgi_info->cgi_error != -1) {
		poll_data[poll_size].fd = cgi_info->cgi_error;
		poll_data[poll_size].events = POLL_EVENT_BITS;
		poll_size++;
	}

	do {
		read_again = false;
		switch (poll((struct pollfd*)&poll_data, poll_size, 1000)) {
			case -1:
				if (errno != EINTR) {
					return cgi_ERROR;
				}
				read_again = true;
				break;
			case 0:
				if (session->force_quit) {
					return cgi_FORCE_QUIT;
				} else if (time(NULL) > cgi_info->deadline) {
					return cgi_TIMEOUT;
				}
				read_again = true;
				break;
		}
	} while (read_again);

	/* Read CGI output
	 */
	if (cgi_info->from_cgi != -1) {
		if (poll_data[0].revents != 0) do {
			read_again = false;

			if ((can_read = cgi_info->input_buffer_size - cgi_info->input_len) <= 0) {
				break;
			}

			bytes_read = read(cgi_info->from_cgi, cgi_info->input_buffer + cgi_info->input_len, can_read);
			switch (bytes_read) {
				case -1:
					if (errno != EINTR) {
						return cgi_ERROR;
					}
					read_again = true;
					break;
				case 0:
					close(cgi_info->from_cgi);
					cgi_info->from_cgi = -1;
					break;
				default:
					cgi_info->input_len += bytes_read;
			}
		} while (read_again);
	}

	/* Read CGI error output
	 */
	if (cgi_info->cgi_error != -1) {
		if (poll_data[1].revents != 0) {
			do {
				read_again = false;

				bytes_read = read(cgi_info->cgi_error, cgi_info->error_buffer + cgi_info->error_len, cgi_info->error_buffer_size - cgi_info->error_len);
				switch (bytes_read) {
					case -1:
						if (errno != EINTR) {
							return cgi_ERROR;
						}
						read_again = true;
						break;
					case 0:
						close(cgi_info->cgi_error);
						cgi_info->cgi_error = -1;
						break;
					default:
						cgi_info->error_len += bytes_read;
				}
			} while (read_again);
		} else if (recv(cgi_info->cgi_error, cgi_info->error_buffer + cgi_info->error_len, cgi_info->error_buffer_size - cgi_info->error_len, MSG_PEEK | MSG_DONTWAIT) <= 0) {
			close(cgi_info->cgi_error);
			cgi_info->cgi_error = -1;
		}
	}

	if ((cgi_info->from_cgi == -1) && (cgi_info->cgi_error == -1)) {
		result = cgi_END_OF_DATA;
	}

	return result;
}

/*
 *  FastCGI servers
 *  ================
 */
int connect_to_fcgi_server(t_connect_to *connect_to) {
	if (connect_to == NULL) {
		return -1;
	}

	if (connect_to->unix_socket != NULL) {
		return connect_to_unix_socket(connect_to->unix_socket);
	} else {
		return connect_to_server(&(connect_to->ip_addr), connect_to->port);
	}
}

int send_fcgi_request(t_session *session, int sock) {
	t_fcgi_buffer fcgi_buffer;
	char buffer[UPLOADED_FILE_BUFFER_SIZE];
	int handle, bytes_read;

	fcgi_buffer.sock = sock;
	fcgi_buffer.size = 0;

	if (write_buffer(sock, "\x01\x01\x00\x01" "\x00\x08\x00\x00" "\x00\x01\x00\x00" "\x00\x00\x00\x00", 16) == -1) {
		return -1;
	}

	fcgi_buffer.type = FCGI_PARAMS;
	set_environment(session, &fcgi_buffer);
	if (send_fcgi_buffer(&fcgi_buffer, NULL, 0) == -1) {
		return -1;
	}

	fcgi_buffer.type = FCGI_STDIN;
	if (session->body != NULL) {
		/* Send POST data to FastCGI program.
		 */
		if (send_fcgi_buffer(&fcgi_buffer, session->body, session->content_length) == -1) {
			return -1;
		}
	} else if (session->uploaded_file != NULL) {
		/* Send uploaded file to FastCGI program
		 */
		if ((handle = open(session->uploaded_file, O_RDONLY)) == -1) {
			return -1;
		}
		while ((bytes_read = read(handle, buffer, UPLOADED_FILE_BUFFER_SIZE)) > 0) {
			if (send_fcgi_buffer(&fcgi_buffer, buffer, bytes_read) == -1) {
				bytes_read = -1;
				break;
			}
		}
		close(handle);

		if (bytes_read == -1) {
			return -1;
		}

	}

	if (send_fcgi_buffer(&fcgi_buffer, NULL, 0) == -1) {
		return -1;
	}

	return 0;
}

static t_cgi_result read_fcgi_socket(t_session *session, t_cgi_info *cgi_info, char *buffer, int size) {
	int bytes_read;
	bool read_again;
	struct pollfd poll_data;

	poll_data.fd = cgi_info->from_cgi;
	poll_data.events = POLL_EVENT_BITS;

	do {
		read_again = false;
		switch (poll(&poll_data, 1, 1000)) {
			case -1:
				if (errno == EINTR) {
					read_again = true;
				}
				break;
			case 0:
				if (session->force_quit) {
					return cgi_FORCE_QUIT;
				} else if (time(NULL) > cgi_info->deadline) {
					return cgi_TIMEOUT;
				}
				read_again = true;
				break;
			default:
				do {
					read_again = false;
					if ((bytes_read = read(cgi_info->from_cgi, buffer, size)) == -1) {
						if (errno != EINTR) {
							break;
						}
						read_again = true;
					}
				} while (read_again);
				return bytes_read;
		}
	} while (read_again);

	return cgi_ERROR;
}

t_cgi_result read_from_fcgi_server(t_session *session, t_cgi_info *cgi_info) {
	char *buffer, *dummy = NULL;
	bool read_again;
	int bytes_read, bytes_left;
	unsigned int content, padding, data_length;
	t_cgi_result result = cgi_OKE;

	/* Read header
	 */
	if (cgi_info->read_header) {
		bytes_left = FCGI_HEADER_LENGTH;
		do {
			read_again = false;

			switch (bytes_read = read_fcgi_socket(session, cgi_info, cgi_info->header + FCGI_HEADER_LENGTH - bytes_left, bytes_left)) {
				case cgi_TIMEOUT:
					return cgi_TIMEOUT;
				case cgi_FORCE_QUIT:
					return cgi_FORCE_QUIT;
				case cgi_ERROR:
					return cgi_ERROR;
				case 0:
					return cgi_END_OF_DATA;
				default:
					if ((bytes_left -= bytes_read) > 0) {
						read_again = true;
					}
			}
		} while (read_again);

		cgi_info->read_header = false;
		cgi_info->fcgi_data_len = 0;
	}

	if (((unsigned char)cgi_info->header[1]) == FCGI_END_REQUEST) {
		return cgi_END_OF_DATA;
	}

	/* Determine the size of the data
	 */
	content = 256 * (unsigned char)cgi_info->header[4] + (unsigned char)cgi_info->header[5];
	padding = (unsigned char)cgi_info->header[6];
	if ((data_length = content + padding) <= 0) {
		cgi_info->read_header = true;
		return cgi_OKE;
	}

	switch ((unsigned char)cgi_info->header[1]) {
		case FCGI_STDOUT:
			buffer = cgi_info->input_buffer + cgi_info->input_len;
			bytes_left = cgi_info->input_buffer_size - cgi_info->input_len;
			break;
		case FCGI_STDERR:
			buffer = cgi_info->error_buffer + cgi_info->error_len;
			bytes_left = cgi_info->error_buffer_size - cgi_info->error_len;
			break;
		default:
			/* Unsupported type, so skip data
			 */
			if ((dummy = (char*)malloc(DUMMY_BUFFER_SIZE)) == NULL) {
				return cgi_ERROR;
			}
			buffer = dummy;
			bytes_left = DUMMY_BUFFER_SIZE;
	}

	/* Read data
	 */
	if ((unsigned int)bytes_left > (data_length - cgi_info->fcgi_data_len)) {
		bytes_left = data_length - cgi_info->fcgi_data_len;
	}

	switch (bytes_read = read_fcgi_socket(session, cgi_info, buffer, bytes_left)) {
		case cgi_TIMEOUT:
			result = cgi_TIMEOUT;
			break;
		case cgi_FORCE_QUIT:
			result = cgi_FORCE_QUIT;
			break;
		case cgi_ERROR:
			result = cgi_ERROR;
			break;
		case 0:
			result = cgi_END_OF_DATA;
			break;
		default:
			if ((cgi_info->fcgi_data_len += bytes_read) == data_length) {
				cgi_info->read_header = true;
			}
			if (cgi_info->fcgi_data_len > content) {
				/* Read more then content (padding)
				 */
				if (cgi_info->fcgi_data_len - bytes_read < content) {
					bytes_read = content - (cgi_info->fcgi_data_len - bytes_read);
				} else {
					bytes_read = 0;
				}
			}
			switch ((unsigned char)cgi_info->header[1]) {
				case FCGI_STDOUT:
					cgi_info->input_len += bytes_read;
					break;
				case FCGI_STDERR:
					cgi_info->error_len += bytes_read;
					break;
				default:
					break;
			}
	}

	check_clear_free(dummy, DUMMY_BUFFER_SIZE);

	return result;
}
