#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>

#define POLL_EVENT_BITS (POLLIN | POLLPRI | POLLHUP)
#define BUFFER_SIZE 16384

/* Connect to server
 */
int connect_server(char *server, int port) {
	int sock;
	struct hostent *hostinfo;
	struct sockaddr_in saddr;

	if ((hostinfo = gethostbyname(server)) != NULL) {
		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) > 0) {
			bzero(&saddr, sizeof(struct sockaddr_in));
			saddr.sin_family = AF_INET;
			saddr.sin_port = htons(port);
			memcpy(&saddr.sin_addr.s_addr, hostinfo->h_addr, 4);
			if (connect(sock, (struct sockaddr*)&saddr, sizeof(struct sockaddr_in)) != -1) {
				return sock;
			}
			close(sock);
		}
	}

	return -1;
}

/* Write complete buffer to socket
 */
int write_buffer(int sock, char *buffer, int len) {
	int bytes_written, total_written = 0;

	while (total_written < len) {
		if ((bytes_written = write(sock, buffer + total_written, len - total_written)) == -1) {
			if (errno != EINTR) {
				return -1;
			}
		} else {
			total_written += bytes_written;
		}
	}

	return 0;
}

/* Forward data to SSH daemon
 */
static int forward_ssh_data(int from_sock, int to_sock) {
	int bytes_read;
	char buffer[BUFFER_SIZE];

	if ((bytes_read = read(from_sock, buffer, BUFFER_SIZE)) <= 0) {
		return -1;
	}

	if (write_buffer(to_sock, buffer, bytes_read) == -1) {
		return -1;
	}

	return 0;
}

/* Main routine
 */
int main(int argc, char* argv[]) {
	int sock, size;
	char buffer[BUFFER_SIZE];
	struct pollfd poll_data[2];
	bool quit = false;

	if (argc <= 2) {
		fprintf(stderr, "Usage: %s <hostname> <proxy authorization>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if ((sock = connect_server(argv[1], 80)) == -1) {
		fprintf(stderr, "Error connecting to webserver.\n");
		return EXIT_FAILURE;
	}

	size = sprintf(buffer,
		"CONNECT localhost:22 HTTP/1.0\r\n"
		"Host: localhost:22\r\n"
		"Proxy-Authorization: Basic %s\r\n"
		"\r\n", argv[2]);
	write_buffer(sock, buffer, size);

	size = read(sock, buffer, BUFFER_SIZE);
	buffer[size] = '\0';

	if (strncmp(buffer, "HTTP/1.0 200", 12) != 0) {
		fprintf(stderr, "Method not allowed by webserver.\n");
		return EXIT_FAILURE;
	}

	poll_data[0].fd = 0;
	poll_data[0].events = POLL_EVENT_BITS;
	poll_data[1].fd = sock;
	poll_data[1].events = POLL_EVENT_BITS;

	do {
		switch (poll(poll_data, 2, 1000)) {
			case -1:
				if (errno != EINTR) {
					quit = true;
				}
				break;
			case 0:
				break;
			default:
				if (poll_data[0].revents != 0) {
					if (forward_ssh_data(0, sock) == -1) {
						quit = true;
					}
				}
				if (poll_data[1].revents != 0) {
					if (forward_ssh_data(sock, 1) == -1) {
						quit = true;
					}
				}
				break;
		}
	} while (quit == false);

	return EXIT_SUCCESS;
}
