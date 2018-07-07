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
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "alternative.h"
#include "libstr.h"
#include "libfs.h"
#include "userconfig.h"

#define DELIMITER ';'

typedef struct type_wrap {
	char *cgiroot;
	char *chroot;
	uid_t uid;
	gid_t gid;
	t_groups groups;
} t_wrap;

static int cgi_pid;

void ALRM_handler() {
	if (kill(cgi_pid, SIGTERM) != -1) {
		sleep(1);
		kill(cgi_pid, SIGKILL);
	}
}

void print_code(int code) {
	switch (code) {
		case -1:
			fprintf(stderr, "CGI-Wrapper v"VERSION"\nOnly the Hiawatha webserver is allowed to execute this program.\n");
			break;
		default:
			printf("Status: %d\r\n\r\n", code);
	}

	exit(EXIT_FAILURE);
}

void log_error(char *str) {
	fprintf(stderr, "CGI-wrapper: %s\n", str);
}

bool get_wrap_data(char *wrapid, char *handler, char *cgi, t_wrap *wrap_data, char *user_directory) {
	FILE *fp;
	char line[257], *item, *rest, *pipe;
	struct passwd *pwd;
	bool wrap_oke = false, handler_oke;
	size_t len, len_ud;

	handler_oke = (handler == NULL);

	wrap_data->chroot = NULL;

	/* WrapID is local userid?
	 */
	if (*wrapid == '~') {
		if ((pwd = getpwnam(wrapid + 1)) == NULL) {
			return false;
		}
		if ((wrap_data->uid = pwd->pw_uid) == 0) {
			return false;
		}
		len = strlen(pwd->pw_dir);
		len_ud = strlen(user_directory);
		if ((wrap_data->cgiroot = (char*)malloc(len + len_ud + 1)) == NULL) {
			return false;
		}
		memcpy(wrap_data->cgiroot, pwd->pw_dir, len);
		strncpy(wrap_data->cgiroot + len, user_directory, len_ud + 1);
		if (strncmp(wrap_data->cgiroot, cgi, strlen(wrap_data->cgiroot)) != 0) {
			return false;
		}
		if (lookup_group_ids(wrap_data->uid, &(wrap_data->gid), &(wrap_data->groups)) == -1) {
			return false;
		}

		if (handler_oke) {
			return true;
		}

		wrap_oke = true;
	} else {
		wrap_data->cgiroot = NULL;
	}

	/* Read CGI wrapper configuration
	 */
	if ((fp = fopen(CONFIG_DIR"/cgi-wrapper.conf", "r")) == NULL) {
		return false;
	}

	line[256] = '\0';

	while (fgets(line, 256, fp) != NULL) {
		rest = uncomment(line);
		if (*rest == '\0') {
			continue;
		}

		if (split_configline(rest, &item, &rest) == 0) {
			strlower(item);
			if (strcmp(item, "cgihandler") == 0) {
				/* CGI handler
				 */
				if (handler_oke) {
					continue;
				}
				do {
					split_string(rest, &item, &rest, ',');
					if (strcmp(handler, item) == 0) {
						handler_oke = true;
						break;
					}
				} while (rest != NULL);
			} else if (strcmp(item, "wrap") == 0) {
				/* Wrap entry
				 */
				if (wrap_oke) {
					continue;
				}

				/* Wrap Id
				 */
				if (split_string(rest, &item, &rest, DELIMITER) == -1) {
					break;
				}
				if (strcmp(item, wrapid) != 0) {
					continue;
				}

				/* Homedirectory
				 */
				if (split_string(rest, &item, &rest, DELIMITER) == -1) {
					break;
				}
				if (*item == '/') {
					/* chroot directory
					 */
					if ((pipe = strchr(item, '|')) != NULL) {
						*pipe = '\0';
						len = pipe - item + 1;
						if ((wrap_data->chroot = (char*)malloc(len)) == NULL) {
							break;
						}
						memcpy(wrap_data->chroot, item, len);
						if (*(pipe + 1) == '\0') {
							*pipe = '\0';
						} else {
							*pipe = '/';
						}
					}

					if ((len = strlen(item)) == 0) {
						break;
					}
					if ((strncmp(item, cgi, len) != 0) || (*(cgi + len) != '/')) {
						log_error("CGI not in WebsiteRoot");
						break;
					}

					if (pipe != NULL) {
						cgi += (pipe - item);
						item = pipe;
					}

					if ((wrap_data->cgiroot = strdup(item)) == NULL) {
						break;
					}
				} else if (*item == '~') {
					if ((pwd = getpwnam(item + 1)) == NULL) {
						log_error("invalid username");
						break;
					}
					len = strlen(pwd->pw_dir);
					len_ud = strlen(user_directory);
					if ((wrap_data->cgiroot = (char*)malloc(len + len_ud + 1)) == NULL) {
						break;
					}
					memcpy(wrap_data->cgiroot, pwd->pw_dir, len);
					strncpy(wrap_data->cgiroot + len, user_directory, len_ud + 1);
					if (strncmp(wrap_data->cgiroot, cgi, strlen(wrap_data->cgiroot)) != 0) {
						log_error("CGI not in user directory");
						break;
					}
				} else {
					log_error("invalid CGI root");
					break;
				}

				/* User Id
				 */
				split_string(rest, &item, &rest, ':');
				if (parse_userid(item, &(wrap_data->uid)) != 1) {
					log_error("invalid userid");
					break;
				}

				/* Group id
				 */
				if (rest != NULL) {
					if (parse_groups(rest, &(wrap_data->gid), &(wrap_data->groups)) != 1) {
						log_error("syntax error in groupid");
						break;
					}
				} else {
					if (lookup_group_ids(wrap_data->uid, &(wrap_data->gid), &(wrap_data->groups)) != 1) {
						log_error("invalid group (user member of root?)");
						break;
					}
				}

				wrap_oke = true;
			} else {
				/* Crap in configurationfile
				 */
				log_error("syntax error in configurationfile");
				break;
			}
			if (wrap_oke && handler_oke) {
				break;
			}
		} else {
			/* split_string() error
			 */
			break;
		}
	}
	fclose(fp);

	if (wrap_oke == false) {
		log_error("no valid Wrap found");
	}

	if (handler_oke == false) {
		log_error("no valid CGIhandler found");
	}

	return wrap_oke && handler_oke;
}

int main(int argc, char *argv[]) {
	char buffer[8], *wrapid, *var, *user_directory;
	FILE *fp;
	int i, handle, arg_offset, time_for_cgi;
	size_t len;
	t_wrap wrap_data;
	bool follow_symlinks = true, usecgi_handler;

	char *cgiwrap_id      = "CGIWRAP_ID";
	char *cgiwrap_symlink = "CGIWRAP_FOLLOWSYMLINKS";
	char *cgiwrap_cgitime = "CGIWRAP_TIMEFORCGI";
	char *cgiwrap_userdir = "CGIWRAP_USERDIRECTORY";

	if (argc < 3) {
		print_code(-1);
	}

	/* Check if parent is Hiawatha
	 */
	buffer[0] = buffer[7] = '\0';
	if ((fp = fopen(PID_DIR"/hiawatha.pid", "r")) == NULL) {
		print_code(-1);
	}
	if (fgets(buffer, 7, fp) == NULL) {
		print_code(-1);
	}
	fclose(fp);

	if ((len = strlen(buffer)) == 0) {
		print_code(-1);
	} else if (buffer[len - 1] != '\n') {
		print_code(-1);
	}
	buffer[len - 1] = '\0';

	if ((i = str_to_int(buffer)) == -1) {
		print_code(-1);
	}
	if (getsid(0) != getsid(i)) {
		print_code(-1);
	}

	/* Read environment settings
	 */
	if ((wrapid = getenv(cgiwrap_id)) == NULL) {
		log_error("getenv(CGIWRAP_ID) error");
		print_code(500);
	}

	if ((var = getenv(cgiwrap_symlink)) == NULL) {
		log_error("getenv(CGIWRAP_FOLLOWSYMLINKS) error");
		print_code(500);
	}
	follow_symlinks = (strcmp(var, "true") == 0);

	if ((var = getenv(cgiwrap_cgitime)) == NULL) {
		time_for_cgi = 5;
	} else if ((time_for_cgi = str_to_int(var)) == -1) {
		print_code(500);
	}

	if ((var = getenv(cgiwrap_userdir)) != NULL) {
		len = strlen(var) + 3;
		if ((user_directory = (char*)malloc(len)) == NULL) {
			print_code(500);
		}
		snprintf(user_directory, len, "/%s/", var);
	} else {
		user_directory = "/public_html/";
	}

	/* Clear environment crap
	 */
	unsetenv(cgiwrap_id);
	unsetenv(cgiwrap_symlink);
	unsetenv(cgiwrap_cgitime);
	unsetenv(cgiwrap_userdir);

	/* Check for bad path
	 */
	if (strstr(argv[1], "/../") != NULL) {
		log_error("/../ in path detected");
		print_code(500);
	}

	/* Read cgi-wrapper config
	 */
	if ((usecgi_handler = (strcmp(argv[0], "-") != 0))) {
		/* CGI handler
		 */
		if (get_wrap_data(wrapid, argv[0], argv[2], &wrap_data, user_directory) == false) {
			print_code(500);
		}
	} else {
		/* CGI program
		 */
		if (get_wrap_data(wrapid, NULL, argv[1], &wrap_data, user_directory) == false) {
			print_code(500);
		}
	}

	/* chroot
	 */
	if (wrap_data.chroot != NULL) {
		if (chdir(wrap_data.chroot) == -1) {
			log_error("chdir(CHROOTDIR) error");
			print_code(404);
		} else if (chroot(wrap_data.chroot) == -1) {
			log_error("chroot() error");
			print_code(500);
		}
		len = strlen(wrap_data.chroot);
		if (usecgi_handler == false) {
			*(argv + 1) += len;
		}
		*(argv + 2) += len;

		setenv("DOCUMENT_ROOT", wrap_data.cgiroot, 1);
		setenv("SCRIPT_FILENAME", argv[2], 1);
	}

	/* Set IDs
	 */
	if (setuid(0) == -1) {
		log_error("setuid(0) error");
		print_code(500);
	} else if (setgroups(wrap_data.groups.number, wrap_data.groups.array) == -1) {
		log_error("setgroups() error");
		print_code(500);
	} else if (setgid(wrap_data.gid) == -1) {
		log_error("setgid() error");
		print_code(500);
	} else if (setuid(wrap_data.uid) == -1) {
		log_error("setuid(uid) error");
		print_code(500);
	}

	/* New session
	 */
	if (setsid() == -1) {
		log_error("setsid() error");
		print_code(500);
	}

	/* Does the CGI program exist?
	 */
	if ((handle = open(argv[2], O_RDONLY)) == -1) {
		if (errno == EACCES) {
			log_error("access to CGI program denied");
			print_code(403);
		}
		log_error("CGI program does not exist");
		print_code(404);
	} else {
		close(handle);
	}

	/* Symlink allowed?
	 */
	if (follow_symlinks == false) {
		switch (contains_not_allowed_symlink(argv[2], wrap_data.cgiroot)) {
			case fb_error:
				log_error("contains_not_allowed_symlink() error");
				print_code(500);
				break;
			case fb_not_found:
				log_error("CGI program not found");
				print_code(404);
				break;
			case fb_no_access:
			case fb_yes:
				log_error("symlinks not allowed");
				print_code(403);
				break;
			case fb_no:
				break;
		}
	}

	/* Check file accessrights
	 */
	if (usecgi_handler == false) {
		switch (can_execute(argv[1], wrap_data.uid, wrap_data.gid, &(wrap_data.groups))) {
			case fb_error:
				log_error("can_execute() error");
				print_code(500);
				break;
			case fb_not_found:
				log_error("CGI program not found");
				print_code(404);
				break;
			case fb_no_access:
			case fb_no:
				log_error("access to CGI program denied");
				print_code(403);
				break;
			case fb_yes:
				break;
		}

		arg_offset = 1;
	} else {
		arg_offset = 0;
	}

	/* And here we go
	 */
	switch (cgi_pid = fork()) {
		case -1:
			log_error("fork() error");
			print_code(500);
			break;
		case 0:
			execvp(argv[arg_offset], argv + 1 + arg_offset);
			log_error("execvp() error");
			print_code(500);
			exit(EXIT_FAILURE);
		default:
			signal(SIGALRM, ALRM_handler);
			alarm(time_for_cgi);
			waitpid(cgi_pid, NULL, 0);
	}

	return 0;
}
