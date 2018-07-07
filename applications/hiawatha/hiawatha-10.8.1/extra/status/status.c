#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PTHREAD_STACK_SIZE 512 * 1024

static bool quit = false;
char *normal = "\033[00m";

int connect_to_tomahawk(int port) {
	int sock = -1;
	struct sockaddr_in saddr4;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
		return -1;
	}

	memset(&saddr4, 0, sizeof(struct sockaddr_in));
	saddr4.sin_family = AF_INET;
	saddr4.sin_addr.s_addr = htonl(0x7F000001);
	saddr4.sin_port = htons(port);

	if (connect(sock, (struct sockaddr*)&saddr4, sizeof(struct sockaddr_in)) != 0) {
		close(sock);
		return -1;
	}

	return sock;
}

void tomahawk_reader(int *sock) {
	char buffer[1024];
	int bytes_read;

	while (quit == false) {
		if ((bytes_read = read(*sock, buffer, 1023)) > 0) {
			buffer[bytes_read] = '\0';
			printf("%s", buffer);
		} else {
			quit = true;
		}
	}

	pthread_exit(NULL);
}

int start_reader_thread(int *socket, pthread_t *child_thread) {
	int result = -1;
	pthread_attr_t child_attr;

	if (pthread_attr_init(&child_attr) != 0) {
		printf("pthread init error\n");
	} else {
		if (pthread_attr_setstacksize(&child_attr, PTHREAD_STACK_SIZE) != 0) {
			printf("pthread set stack size error");
		} else if (pthread_create(child_thread, &child_attr, (void*)tomahawk_reader, (void*)socket) != 0) {
			printf("pthread create error");
		} else {
			result = 0;
		}
		pthread_attr_destroy(&child_attr);
	}

	return result;
}

int send_command(int sock, char *command) {
	if (send(sock, command, strlen(command), 0) == -1) {
		return -1;
	}

	printf("%s\n", command);

	return 0;
}

void TERM_handler() {
	quit = true;
}

int main(int argc, char *argv[]) {
	int sock, port, delay = 3;
	pthread_t child_thread;
	char *password;

	if (argc <= 2) {
		printf("Usage: %s <Tomahawk port> <password> [<seconds=%d>]\n", argv[0], delay);
		return EXIT_FAILURE;
	}

	if ((port = atoi(argv[1])) <= 0) {
		fprintf(stderr, "Invalid port number.\n");
		return EXIT_FAILURE;
	}
	password = argv[2];

	if (argc >= 4) {
		if ((delay = atoi(argv[3])) <= 0) {
			fprintf(stderr, "Invalid delay seconds.\n");
			return EXIT_FAILURE;
		}
	}

	if ((sock = connect_to_tomahawk(port)) == -1) {
		fprintf(stderr, "Error connecting to Tomahawk.\n");
		return EXIT_FAILURE;
	}

	signal(SIGINT, TERM_handler);

	if (start_reader_thread(&sock, &child_thread) == -1) {
		fprintf(stderr, "Error starting reader thread.\n");
		return EXIT_FAILURE;
	}

	send(sock, password, strlen(password), 0);
	send(sock, "\n", 1, 0);

	while (quit == false) {
		send_command(sock, "clear screen\n");
		usleep(50000);
		send_command(sock, "show status\n");
		sleep(delay);
	}

	send_command(sock, "quit\n");

	pthread_join(child_thread, NULL);

	return EXIT_SUCCESS;
}
