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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <grp.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#include <sys/socket.h>
#include <sys/resource.h>
#include "global.h"
#include "alternative.h"
#include "mimetype.h"
#include "serverconfig.h"
#include "cgi.h"
#include "session.h"
#include "workers.h"
#include "send.h"
#include "client.h"
#include "log.h"
#include "global.h"
#include "httpauth.h"
#include "tomahawk.h"
#include "tls.h"
#include "cache.h"
#include "xslt.h"
#include "monitor.h"
#include "memdbg.h"
#include "challenge.h"

#define rs_NONE                  0
#define rs_QUIT_SERVER           1
#define rs_UNBAN_CLIENTS         2
#define rs_UNLOCK_LOGFILES       3
#define rs_CLEAR_CACHE           4

#define MAX_TOMAHAWK_CONNECTIONS 3

typedef struct {
	char *config_dir;
	bool daemon;
	bool config_check;
} t_settings;

static volatile int received_signal = rs_NONE;
static bool must_quit = false;
#ifdef ENABLE_LOADCHECK
static double current_server_load = 0;
#endif

char *fb_symlink     = "symlink not allowed";
char *version_string = "Hiawatha v"VERSION;
char *enabled_modules = ""
#ifdef ENABLE_CACHE
	", Cache"
#endif
#ifdef ENABLE_CHALLENGE
	", ChallengeClient"
#endif
#ifdef ENABLE_DEBUG
	", debug"
#endif
#ifdef ENABLE_FILEHASHES
	", FileHashes"
#endif
#ifdef ENABLE_IPV6
	", IPv6"
#endif
#ifdef ENABLE_MONITOR
	", Monitor"
#endif
#ifdef ENABLE_RPROXY
	", ReverseProxy"
#endif
#ifdef ENABLE_TLS
	", TLS v"MBEDTLS_VERSION_STRING
#endif
#ifdef ENABLE_THREAD_POOL
	", ThreadPool"
#endif
#ifdef ENABLE_TOMAHAWK
	", Tomahawk"
#endif
#ifdef ENABLE_TOOLKIT
	", UrlToolkit"
#endif
#ifdef ENABLE_XSLT
	", XSLT"
#endif
;

/* Create all logfiles with the right ownership and accessrights
 */
void create_logfile(char *logfile, mode_t mode, uid_t uid, gid_t gid) {
	if (logfile != NULL) {
		if (create_file(logfile, mode, uid, gid) != 0) {
			fprintf(stderr, "Error creating logfile %s or changing its protection or ownership.\n", logfile);
		}
	}
}

void create_logfiles(t_config *config) {
	t_host *host;

	create_logfile(config->system_logfile, LOG_PERM, config->server_uid, config->server_gid);
	create_logfile(config->garbage_logfile, LOG_PERM, config->server_uid, config->server_gid);
	create_logfile(config->exploit_logfile, LOG_PERM, config->server_uid, config->server_gid);
#ifdef ENABLE_DEBUG
	create_logfile(TLS_ERROR_LOGFILE, LOG_PERM, config->server_uid, config->server_gid);
#endif

	host = config->first_host;
	while (host != NULL) {
		if (host->access_fileptr != NULL) {
			fflush(host->access_fileptr);
		}

		create_logfile(host->access_logfile, LOG_PERM, config->server_uid, config->server_gid);
		create_logfile(host->error_logfile, LOG_PERM, config->server_uid, config->server_gid);
		host = host->next;
	}
}

/* Task-runner starts periodic tasks
 */
void task_runner(t_config *config) {
	t_ip_addr ip_addr;
	int delay = 0;
	time_t now;
#ifdef ENABLE_LOADCHECK
	FILE *load_fp = NULL;
	char load_str[50], *c;
#ifdef ENABLE_MONITOR
	int  load_monitor_timer = 0;
#endif
#endif

	do {
		sleep(1);

		if (delay >= TASK_RUNNER_INTERVAL) {
			now = time(NULL);

#ifdef ENABLE_MEMDBG
			/* Print memory usage
			 */
		    memdbg_print_log(true);
#endif

#ifdef ENABLE_THREAD_POOL
			/* Manage thread pool
			 */
			manage_thread_pool(config->thread_pool_size, config->thread_kill_rate);
#endif

			/* Client checks
			 */
			check_ban_list(config, now);
			check_remove_deadlines(config, now);
			remove_wrong_password_list(config);

			/* FastCGI check
			 */
			manage_load_balancer(config, now);

			/* Close idle logfile handles
			 */
			close_logfiles(config->first_host, now);

#ifdef ENABLE_CACHE
			/* Cache check
			 */
			manage_cache(now);
#endif

#ifdef ENABLE_MONITOR
			/* Monitor stats
			 */
			if (config->monitor_enabled) {
				monitor_stats_to_buffer(config, now);
			}
#endif

			/* Rotate access logfiles
			 */
			if (config->rotate_access_logs) {
				rotate_access_logfiles(config, now);
			}

			delay = 0;
		} else {
			delay++;
		}

#ifdef ENABLE_TOMAHAWK
		/* Tomahawk check
		 */
		check_admin_list();
#endif

#ifdef ENABLE_LOADCHECK
		if (config->max_server_load > 0) {
			if ((load_fp = fopen("/proc/loadavg", "r")) != NULL) {
				if (fgets(load_str, 49, load_fp) != NULL) {
					load_str[49] = '\0';
					if ((c = strchr(load_str, ' ')) != NULL) {
						*c = '\0';
						current_server_load = atof(load_str);
#ifdef ENABLE_MONITOR
						if (config->monitor_enabled) {
							if ((current_server_load > config->max_server_load) && (load_monitor_timer == 0)) {
								monitor_event("High server load (%0.2f)", current_server_load);
								load_monitor_timer = 60;
							}
						}
#endif
					} else {
						current_server_load = 0;
					}
				} else {
					current_server_load = 0;
				}

				fclose(load_fp);
			} else {
				current_server_load = 0;
			}

#ifdef ENABLE_MONITOR
			if (load_monitor_timer > 0) {
				load_monitor_timer--;
			}
#endif
		}
#endif

		switch (received_signal) {
			case rs_NONE:
				break;
			case rs_QUIT_SERVER:
				must_quit = true;
				break;
			case rs_UNBAN_CLIENTS:
				default_ipv4(&ip_addr);
				unban_ip(&ip_addr);
#ifdef ENABLE_IPV6
				default_ipv6(&ip_addr);
				unban_ip(&ip_addr);
#endif
				received_signal = rs_NONE;
				break;
			case rs_UNLOCK_LOGFILES:
				close_logfiles(config->first_host, 0);
				received_signal = rs_NONE;
				break;
#ifdef ENABLE_CACHE
			case rs_CLEAR_CACHE:
				clear_cache();
				received_signal = rs_NONE;
				break;
#endif
		}
	} while (must_quit == false);

	pthread_exit(NULL);
}

/* Signal handlers
 */
void SEGV_handler() {
	syslog(LOG_DAEMON | LOG_ALERT, "segmentation fault!");
#ifdef ENABLE_MONITOR
	monitor_event("Server crash!");
	shutdown_monitor_module();
#endif
	exit(EXIT_FAILURE);
}

void TERM_handler() {
	received_signal = rs_QUIT_SERVER;
}

void HUP_handler() {
	received_signal = rs_UNLOCK_LOGFILES;
}

void USR1_handler() {
	received_signal = rs_UNBAN_CLIENTS;
}

#ifdef ENABLE_CACHE
void USR2_handler() {
	received_signal = rs_CLEAR_CACHE;
}
#endif

/* Create a socketlist.
 */
int bind_sockets(t_binding *binding) {
	char ip_address[MAX_IP_STR_LEN], separator;
	struct sockaddr_in  saddr4;
#ifdef ENABLE_IPV6
	struct sockaddr_in6 saddr6;
#endif
	int domain, optval, result;

	while (binding != NULL) {
#ifdef ENABLE_IPV6
		domain = (binding->interface.family == AF_INET ? PF_INET : PF_INET6);
#else
		domain = PF_INET;
#endif
		if ((binding->socket = socket(domain, SOCK_STREAM, 0)) == -1) {
			perror("socket()");
			return -1;
		}

		optval = 1;
		if (setsockopt(binding->socket, SOL_SOCKET, SO_REUSEADDR, (void*)&optval, sizeof(int)) == -1) {
			perror("setsockopt(SOL_SOCKET, SO_REUSEADDR)");
		}

		optval = 1;
		if (setsockopt(binding->socket, IPPROTO_TCP, TCP_NODELAY, (void*)&optval, sizeof(int)) == -1) {
			perror("setsockopt(IPPROTO_TCP, TCP_NODELAY)");
		}

		if (binding->interface.family == AF_INET) {
			/* IPv4
			 */
			memset(&saddr4, 0, sizeof(struct sockaddr_in));
			saddr4.sin_family = AF_INET;
			memcpy(&(saddr4.sin_addr.s_addr), &(binding->interface.value), IPv4_LEN);
			saddr4.sin_port = htons(binding->port);

			result = bind(binding->socket, (struct sockaddr*)&saddr4, sizeof(struct sockaddr_in));

			separator = ':';
#ifdef ENABLE_IPV6
		} else if (binding->interface.family == AF_INET6) {
			/* IPv6
			 */
			optval = 1;
			if (setsockopt(binding->socket, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(int)) < 0) {
				perror("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY)");
			}

			memset(&saddr6, 0, sizeof(struct sockaddr_in6));
			saddr6.sin6_family = AF_INET6;
			memcpy(&(saddr6.sin6_addr.s6_addr), &(binding->interface.value), IPv6_LEN);
			saddr6.sin6_port = htons(binding->port);

			result = bind(binding->socket, (struct sockaddr*)&saddr6, sizeof(struct sockaddr_in6));

			separator = '.';
#endif
		} else {
			fprintf(stderr, "Unknown protocol (family %d).\n", binding->interface.family);
			return -1;
		}

		if (result == -1) {
			/* Handle error
		 	 */
			if (inet_ntop(binding->interface.family, &(binding->interface.value), ip_address, MAX_IP_STR_LEN) == NULL) {
				strcpy(ip_address, "?.?.?.?");
			}
			fprintf(stderr, "Error binding %s%c%d\n", ip_address, separator, binding->port);
			return -1;
		}

		binding = binding->next;
	}

	return 0;
}

/* Accept or deny an incoming connection.
 */
int accept_connection(t_binding *binding, t_config *config) {
	socklen_t           size;
	bool                kick_client;
	t_session           *session;
	struct sockaddr_in  caddr4;
#ifdef ENABLE_IPV6
	struct sockaddr_in6 caddr6;
#endif
	int                 optval, connections_per_ip, total_connections;
	struct timeval      timer;
#ifdef ENABLE_DEBUG
	static int          thread_id = 1;
#endif

	if ((session = (t_session*)malloc(sizeof(t_session))) == NULL) {
		return -1;
	}
#ifdef ENABLE_DEBUG
	session->thread_id = thread_id++;
	session->current_task = "new";
#endif
	session->config = config;
	session->binding = binding;
	init_session(session);

	if (binding->interface.family == AF_INET) {
		/* IPv4
		 */
		size = sizeof(struct sockaddr_in);
		memset((void*)&caddr4, 0, (size_t)size);
		if ((session->client_socket = accept(binding->socket, (struct sockaddr*)&caddr4, &size)) == -1) {
			free(session);
			log_system(config, "Error accepting incoming IPv4 connection: %s", strerror(errno));
			if (errno == EINTR) {
				return 0;
			}
			return -1;
		}

		session->ip_address.family = AF_INET;
		session->ip_address.size   = IPv4_LEN;
		memcpy(&(session->ip_address.value), (char*)&caddr4.sin_addr.s_addr, session->ip_address.size);
#ifdef ENABLE_IPV6
	} else if (binding->interface.family == AF_INET6) {
		/* IPv6
		 */
		size = sizeof(struct sockaddr_in6);
		memset((void*)&caddr6, 0, (size_t)size);
		if ((session->client_socket = accept(binding->socket, (struct sockaddr*)&caddr6, &size)) == -1) {
			free(session);
			log_system(config, "Error accepting incoming IPv6 connection: %s", strerror(errno));
			if (errno == EINTR) {
				return 0;
			}
			return -1;
		}

		session->ip_address.family = AF_INET6;
		session->ip_address.size   = IPv6_LEN;
		memcpy(&(session->ip_address.value), (char*)&caddr6.sin6_addr.s6_addr, session->ip_address.size);
#endif
	} else {
		log_system_session(session, "Incoming connection via unknown protocol");
		free(session);
		return -1;
	}

	session->request_limit = (ip_allowed(&(session->ip_address), session->config->request_limit_mask) != deny);

#ifdef ENABLE_LOADCHECK
	if ((session->config->max_server_load > 0) && session->request_limit) {
		if (current_server_load > session->config->max_server_load) {
			close(session->client_socket);
			free(session);
			log_system(config, "Connection dropped due to high server load.");
			return -1;
		}
	}
#endif

	if (in_iplist(config->hide_proxy, &(session->ip_address))) {
		session->via_trusted_proxy = true;
	}

	if (session->request_limit == false) {
		connections_per_ip = config->total_connections;
	} else {
		connections_per_ip = config->connections_per_ip;
	}

	kick_client = true;

	if ((total_connections = connection_allowed(&(session->ip_address), session->via_trusted_proxy, connections_per_ip, config->total_connections)) >= 0) {
		if (total_connections < (config->total_connections >> 2)) {
			optval = 1;
			if (setsockopt(session->client_socket, IPPROTO_TCP, TCP_NODELAY, (void*)&optval, sizeof(int)) == -1) {
				close(session->client_socket);
				free(session);
				log_system(config, "error setsockopt(TCP_NODELAY)");
				return -1;
			}
		}

		if (config->socket_send_timeout > 0) {
			timer.tv_sec  = config->socket_send_timeout;
			timer.tv_usec = 0;
			if (setsockopt(session->client_socket, SOL_SOCKET, SO_SNDTIMEO, &timer, sizeof(struct timeval)) == -1) {
				close(session->client_socket);
				free(session);
				log_system(config, "error setsockopt(SO_SNDTIMEO)");
				return -1;
			}
		}

		/* Start worker
		 */
		if (start_worker(session) == 0) {
			kick_client = false;
		}
	} else {
		handle_connection_not_allowed(session, total_connections);
	}

	if (kick_client) {
		close(session->client_socket);
		free(session);
	}

	return 0;
}

/* Change UID and GID
 */
int change_uid_gid(t_config *config) {
	if (setgroups(config->groups.number, config->groups.array) == -1) {
		return -1;
	}

	if (setgid(config->server_gid) == -1) {
		return -1;
	}

	if (setuid(config->server_uid) == -1) {
		return -1;
	}

	return 0;
}

/* Run the Hiawatha webserver.
 */
int run_webserver(t_settings *settings) {
	int                number_of_bindings = 0;
	pthread_attr_t     task_runner_attr;
	pthread_t          task_runner_thread;
	struct pollfd      *poll_data, *current_poll;
#ifdef ENABLE_TOMAHAWK
	int                number_of_admins;
	struct sockaddr_in caddr;
	socklen_t          size;
	int                admin_socket;
	FILE               *admin_fp;
#endif
	pid_t              pid;
	t_binding          *binding;
	t_config           *config;
	mode_t             access_rights;
#ifndef CYGWIN
	struct rlimit      resource_limit;
#endif
#ifdef ENABLE_TLS
	t_host             *host;
	t_tls_setup        tls_setup;
#endif
#ifdef HAVE_ACCF
	struct accept_filter_arg afa;
#endif

	/* Read configuration
	 */
	if (init_config_module(settings->config_dir) == -1) {
		perror("init_config_module()");
		return -1;
	} else if ((config = default_config()) == NULL) {
		perror("default_config()");
		return -1;
	} else if (chdir(settings->config_dir) == -1) {
		perror(settings->config_dir);
		return -1;
	} else if (settings->config_check) {
		printf("Using %s\n", settings->config_dir);
	}

	if (read_main_configfile("hiawatha.conf", config, settings->config_check) == -1) {
		return -1;
	} else if (check_configuration(config) == -1) {
		return -1;
	}

	if (read_mimetypes(config->mimetype_config, &(config->mimetype), settings->config_check) == -1) {
		fprintf(stderr, "Error while reading mimetype configuration.\n");
		return -1;
	}

	if (settings->config_check) {
		printf("Configuration OK.\n");
		return 0;
	}

	/* Bind Serverports
	 */
	if (bind_sockets(config->binding) == -1) {
		return -1;
	}

#ifdef ENABLE_TLS
	if (init_tls_module(config->ca_certificates) == -1) {
		return -1;
	}

	tls_setup.min_tls_version = config->min_tls_version;
	tls_setup.dh_size         = config->dh_size;
#endif

	/* Load private keys and certificate for bindings
	 */
	binding = config->binding;
	while (binding != NULL) {
#ifdef ENABLE_TLS
		if (binding->use_tls) {
			if (tls_load_key_cert(binding->key_cert_file, &(binding->private_key), &(binding->certificate)) != 0) {
				return -1;
			}

			if (binding->ca_cert_file != NULL) {
				if (tls_load_ca_cert(binding->ca_cert_file, &(binding->ca_certificate)) != 0) {
					return -1;
				}
				if (binding->ca_crl_file != NULL) {
					if (tls_load_ca_crl(binding->ca_crl_file, &(binding->ca_crl)) != 0) {
						return -1;
					}
				}
			}

			tls_setup.private_key    = binding->private_key;
			tls_setup.certificate    = binding->certificate;
			tls_setup.ca_certificate = binding->ca_certificate;
			tls_setup.ca_crl         = binding->ca_crl;

			if (tls_set_config(&(binding->tls_config), &tls_setup) != 0) {
				return -1;
			}
		}
#endif

		number_of_bindings++;
		binding = binding->next;
	}

#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		number_of_bindings++;
		binding = binding->next;
	}
#endif

#ifdef ENABLE_TLS
	host = config->first_host;
	while (host != NULL) {
		/* Load private key and certificates for virtual hosts
		 */
		if (host->key_cert_file != NULL) {
			if (tls_load_key_cert(host->key_cert_file, &(host->private_key), &(host->certificate)) != 0) {
				return -1;
			}
		}

		if (host->ca_cert_file != NULL) {
			if (tls_load_ca_cert(host->ca_cert_file, &(host->ca_certificate)) != 0) {
				return -1;
			}
			if (host->ca_crl_file != NULL) {
				if (tls_load_ca_crl(host->ca_crl_file, &(host->ca_crl)) != 0) {
					return -1;
				}
			}
		}

		if (host->hpkp_data != NULL) {
			if (create_hpkp_header(host->hpkp_data) == -1) {
				fprintf(stderr, "Error generating HPKP header for %s.\n", host->hostname.item[0]);
				return -1;
			}
			host->hpkp_data->next = NULL;
		}

		/* Initialize Server Name Indication
		 */
		if ((host->private_key != NULL) && (host->certificate != NULL)) {
			tls_setup.private_key    = host->private_key;
			tls_setup.certificate    = host->certificate;
			tls_setup.ca_certificate = host->ca_certificate;
			tls_setup.ca_crl         = host->ca_crl;

			if (tls_register_sni(&(host->hostname), &tls_setup) == -1) {
				return -1;
			}
		}

		host = host->next;
	}
#endif

#ifdef ENABLE_TOMAHAWK
	/* Bind Tomahawk
	 */
	if (bind_sockets(config->tomahawk_port) == -1) {
		return -1;
	}
#endif

	/* Misc settings
	 */
	tzset();
	clearenv();

	/* Become a daemon
	 */
	if (settings->daemon) {
		switch (pid = fork()) {
			case -1:
				perror("fork()");
				return -1;
			case 0:
				if (setsid() == -1) {
					perror("setsid()");
					return -1;
				}
				break;
			default:
				log_pid(config, pid, config->server_uid);
				return 0;
		}
	} else {
		log_pid(config, getpid(), config->server_uid);
	}

	/* Create work directory
	 */
	if (create_directory(config->work_directory, S_IRWXU, config->server_uid, config->server_gid) == -1) {
		fprintf(stderr, "Error creating work directory '%s'\n", config->work_directory);
		return -1;
	}

	/* Create gzipped work directory
	 */
	if (create_directory(config->gzipped_directory, S_IRWXU, config->server_uid, config->server_gid) == -1) {
		fprintf(stderr, "Error creating gzip work directory '%s'\n", config->gzipped_directory);
		return -1;
	}

	wipe_directory(config->gzipped_directory, ".gz");

	/* Create the upload directory for PUT requests
	 */
	if ((getuid() == 0) || (geteuid() == 0)) {
		access_rights = S_ISVTX | S_IRWXU | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH;
	} else {
		access_rights = S_ISVTX | S_IWUSR | S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH;
	}

	if (create_directory(config->upload_directory, access_rights, 0, 0) != 0) {
		fprintf(stderr, "Error creating upload directory '%s'\n", config->upload_directory);
		return -1;
	}

#ifdef ENABLE_MONITOR
	/* Create monitor cache directory
	 */
	if (config->monitor_enabled) {
		if (create_directory(config->monitor_directory, S_IRWXU, config->server_uid, config->server_gid) != 0) {
			fprintf(stderr, "Error creating monitor cache directory %s or changing its protection or ownership.\n", config->monitor_directory);
			return -1;
		}
	}
#endif

	/* Initialize random generator
	 */
	srand((unsigned)time(NULL));

	/* Create logfiles
	 */
	create_logfiles(config);

#ifndef CYGWIN
	/* Set resource limits
	 */
	if (config->set_rlimits) {
		resource_limit.rlim_max = resource_limit.rlim_cur = config->total_connections + 3;
		if (setrlimit(RLIMIT_NPROC, &resource_limit) != 0) {
			fprintf(stderr, "Error setting RLIMIT_NPROC.\n");
		}

		/* system: system.log, exploit.log, garbage.log, debug.log, all bindings, tomahawk connections
		 * per child: socket, access.log, error.log, 3 CGI pipes
		 */
		resource_limit.rlim_max = resource_limit.rlim_cur = 4 + number_of_bindings + MAX_TOMAHAWK_CONNECTIONS +
															6 * config->total_connections;
		if (setrlimit(RLIMIT_NOFILE, &resource_limit) != 0) {
			fprintf(stderr, "Error setting RLIMIT_NOFILE.\n");
		}
	}

	/* Change user and group id
	 */
	if ((getuid() == 0) || (geteuid() == 0)) {
		if (change_uid_gid(config) == -1) {
			fprintf(stderr, "\nError while changing uid/gid!\n");
			return -1;
		}
	}
#endif

	/* Set signal handlers
	 */
	if (settings->daemon == false) {
		printf("Press Ctrl-C to shutdown the Hiawatha webserver.\n");
		signal(SIGINT, TERM_handler);
	} else {
		signal(SIGINT, SIG_IGN);
	}
	if (config->wait_for_cgi == false) {
		signal(SIGCHLD, SIG_IGN);
	}
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGABRT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGSEGV, SEGV_handler);
	signal(SIGTERM, TERM_handler);
	signal(SIGHUP,  HUP_handler);
	signal(SIGUSR1, USR1_handler);
#ifdef ENABLE_CACHE
	signal(SIGUSR2, USR2_handler);
#endif

	/* Start listening for incoming connections
	 */
	binding = config->binding;
	while (binding != NULL) {
		if (listen(binding->socket, config->listen_backlog) == -1) {
			perror("listen(http(s))");
			return -1;
		}
		binding = binding->next;
	}
#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		if (listen(binding->socket, 1) == -1) {
			perror("listen(tomahawk)");
			return -1;
		}
		binding = binding->next;
	}
#endif

#ifdef ENABLE_THREAD_POOL
	if (init_workers_module(config->thread_pool_size) == -1) {
		fprintf(stderr, "Error initializing workers module.\n");
		return -1;
	}
#endif
	if (init_httpauth_module() == -1) {
		fprintf(stderr, "Error initializing HTTP authentication module.\n");
		return -1;
	}
	init_send_module();
	if (init_log_module() == -1) {
		fprintf(stderr, "Error initializing log module.\n");
		return -1;
	}
	if (init_client_module() == -1) {
		fprintf(stderr, "Error initializing client module.\n");
		return -1;
	}
	if (init_load_balancer(config->fcgi_server) == -1) {
		fprintf(stderr, "Error initializing FastCGI load balancer.\n");
		return -1;
	}
#ifdef ENABLE_CACHE
	if (init_cache_module() == -1) {
		fprintf(stderr, "Error initializing cache module.\n");
		return -1;
	}
#endif
#ifdef ENABLE_TOMAHAWK
	if (init_tomahawk_module() == -1) {
		fprintf(stderr, "Error initializing Tomahawk module.\n");
		return -1;
	}
#endif
#ifdef ENABLE_XSLT
	init_xslt_module();
#endif
#ifdef ENABLE_RPROXY
	if (init_rproxy_module() == -1) {
		fprintf(stderr, "Error initializing reverse proxy module.\n");
		return -1;
	}
#endif
	if (init_sqli_detection() == -1) {
		fprintf(stderr, "Error initializing SQL injection detection.\n");
		return -1;
	}
#ifdef ENABLE_MONITOR
	if (config->monitor_enabled) {
		if (init_monitor_module(config) == -1) {
			fprintf(stderr, "Error initializing Monitor module.\n");
			return -1;
		}
		monitor_event("Server start");
		monitor_version(version_string, enabled_modules);
	}
#endif
#ifdef ENABLE_MEMDBG
	init_memdbg();
#endif
#ifdef ENABLE_CHALLENGE
	if (init_challenge_module(config->challenge_secret) == -1) {
		fprintf(stderr, "Error initializing ChallengeClient module.\n");
		return -1;
	}
#endif

#ifdef HAVE_ACCF
	binding = config->binding;
	while (binding != NULL) {
		if (binding->enable_accf
#ifdef ENABLE_TLS
			&& (binding->use_tls == false)
#endif
		) {
			bzero(&afa, sizeof(afa));
			strcpy(afa.af_name, "httpready");
			if (setsockopt(binding->socket, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) == -1) {
				fprintf(stderr, "Error while enabling HTTP accept filter. Kernel module 'accf_http' loaded?");
				return -1;
			}
		}
		binding = binding->next;
	}
#endif

	/* Redirecting I/O to /dev/null
	 */
	if (settings->daemon) {
		if (close(STDIN_FILENO) == -1) {
			fprintf(stderr, "Warning: error closing STDIN\n");
		} else if (open("/dev/null", O_RDONLY) == -1) {
			fprintf(stderr, "Warning: error redirecting stdin\n");
		}
		if (close(STDOUT_FILENO) == -1) {
			fprintf(stderr, "Warning: error closing STDOUT\n");
		} else if (open("/dev/null", O_WRONLY) == -1) {
			fprintf(stderr, "Warning: error redirecting stdout\n");
		}
		if (close(STDERR_FILENO) == -1) {
			fprintf(stderr, "Warning: error closing STDERR\n");
		} else if (open("/dev/null", O_WRONLY) == -1) {
			log_system(config, "Warning: error redirecting stderr\n");
		}
	}

	log_system(config, "Hiawatha v"VERSION" started.");

	/* Start task_runner
	 */
	if (pthread_attr_init(&task_runner_attr) != 0) {
		log_system(config, "Task-runner pthread init error.");
		return -1;
	} else if (pthread_attr_setdetachstate(&task_runner_attr, PTHREAD_CREATE_DETACHED) != 0) {
		log_system(config, "Task-runner pthread set detach state error.");
		return -1;
	} else if (pthread_attr_setstacksize(&task_runner_attr, PTHREAD_STACK_SIZE) != 0) {
		log_system(config, "Task-runner pthread set stack size error.");
		return -1;
	} else if (pthread_create(&task_runner_thread, &task_runner_attr, (void*)task_runner, (void*)config) != 0) {
		log_system(config, "Task-runner pthread create error.");
		return -1;
	}
	pthread_attr_destroy(&task_runner_attr);

#ifdef ENABLE_MEMDBG
	/* Clear memory debugger log
	 */
	memdbg_clear_log();
#endif

	/* Setup poll data
	 */
	if ((poll_data = (struct pollfd*)malloc((number_of_bindings + MAX_TOMAHAWK_CONNECTIONS) * sizeof(struct pollfd))) == NULL) {
		return -1;
	}

	current_poll = poll_data;

	binding = config->binding;
	while (binding != NULL) {
		current_poll->fd = binding->socket;
		current_poll->events = POLL_EVENT_BITS;
		binding->poll_data = current_poll;

		current_poll++;
		binding = binding->next;
	}

#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		current_poll->fd = binding->socket;
		current_poll->events = POLL_EVENT_BITS;
		binding->poll_data = current_poll;

		current_poll++;
		binding = binding->next;
	}
#endif

	/* Main loop
	 */
	do {
#ifdef ENABLE_TOMAHAWK
		current_poll = poll_data + number_of_bindings;
		number_of_admins = prepare_admins_for_poll(current_poll);

		switch (poll(poll_data, number_of_bindings + number_of_admins, 1000)) {
#else
		switch (poll(poll_data, number_of_bindings, 1000)) {
#endif
			case -1:
				if (errno != EINTR) {
					log_system(config, "Fatal error selecting connection.");
					usleep(1000);
				}
				break;
			case 0:
				break;
			default:
#ifdef ENABLE_TOMAHAWK
				/* Connected admins */
				handle_admins(config);
#endif

				/* HTTP(S) ports */
				binding = config->binding;
				while (binding != NULL) {
					if (binding->poll_data->revents != 0) {
						if (accept_connection(binding, config) != 0) {
							usleep(1000);
							break;

						}
					}
					binding = binding->next;
				}

#ifdef ENABLE_TOMAHAWK
				/* Tomahawk ports */
				binding = config->tomahawk_port;
				while (binding != NULL) {
					if (binding->poll_data->revents != 0) {
						size = sizeof(struct sockaddr_in);
						memset((void*)&caddr, 0, (size_t)size);
						if ((admin_socket = accept(binding->socket, (struct sockaddr*)&caddr, &size)) == -1) {
							if (errno != EINTR) {
								log_system(config, "Fatal error accepting Tomahawk connection.");
								usleep(1000);
								break;
							}
						} else if (number_of_admins >= MAX_TOMAHAWK_CONNECTIONS) {
							if ((admin_fp = fdopen(admin_socket, "r+")) != NULL) {
								fprintf(admin_fp, "Maximum number of admin connections reached.\n\n");
								fclose(admin_fp);
							} else {
								close(admin_socket);
							}
						} else if (add_admin(admin_socket) == -1) {
							close(admin_socket);
						}
					}
					binding = binding->next;
				}
#endif
		}
	} while (must_quit == false);

	signal(SIGTERM, SIG_DFL);

	close_bindings(config->binding);

	disconnect_clients(config);
#ifdef ENABLE_TOMAHAWK
	disconnect_admins();
#endif

#ifdef ENABLE_TOMAHAWK
	binding = config->tomahawk_port;
	while (binding != NULL) {
		close(binding->socket);
		binding = binding->next;
	}
#endif

#ifdef ENABLE_MONITOR
	if (config->monitor_enabled) {
		monitor_event("Server stop");
		shutdown_monitor_module();
	}
#endif

	log_system(config, "Hiawatha v"VERSION" stopped.");
	close_logfiles(config->first_host, 0);

	free(poll_data);

	return 0;
}

void show_help(char *hiawatha) {
	printf("Usage: %s [options]\n", hiawatha);
	printf("Options: -c <path>: path to where the configrationfiles are located.\n");
	printf("         -d: don't fork to the background.\n");
	printf("         -h: show this information and exit.\n");
	printf("         -k: check configuration and exit.\n");
	printf("         -m: show enabled modules and exit.\n");
	printf("         -v: show version and copyright and exit.\n");
}

/* Main and stuff...
 */
int main(int argc, char *argv[]) {
	int i = 0;
	t_settings settings;

	/* Default settings
	 */
	settings.config_dir   = CONFIG_DIR;
	settings.daemon       = true;
	settings.config_check = false;

	/* Read command line parameters
	 */
	while (++i < argc) {
		if (strcmp(argv[i], "-c") == 0) {
			if (++i < argc) {
				settings.config_dir = argv[i];
			} else {
				fprintf(stderr, "Specify a directory.\n");
				return EXIT_FAILURE;
			}
		} else if (strcmp(argv[i], "-d") == 0) {
			settings.daemon = false;
		} else if (strcmp(argv[i], "-h") == 0) {
			show_help(argv[0]);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[i], "-k") == 0) {
			settings.config_check = true;
		} else if (strcmp(argv[i], "-m") == 0) {
			if (strlen(enabled_modules) == 0) {
				enabled_modules = "none";
			} else {
				enabled_modules += 2;
			}
			printf("Enabled modules: %s\n", enabled_modules);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[i], "-v") == 0) {
			printf("%s, copyright (c) by Hugo Leisink <hugo@leisink.net>\n", version_string);
			return EXIT_SUCCESS;
		} else {
			fprintf(stderr, "Unknown option. Use '-h' for help.\n");
			return EXIT_FAILURE;
		}
	}

	/* Run Hiawatha
	 */
	if (run_webserver(&settings) == -1) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
