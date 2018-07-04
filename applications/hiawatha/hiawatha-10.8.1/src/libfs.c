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
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <zlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "global.h"
#include "libfs.h"
#include "libstr.h"
#include "memdbg.h"

static char *months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/* Return the size of a file.
 */
off_t filesize(char *filename) {
	struct stat status;

	if (filename == NULL) {
		return -1;
	} else if (stat(filename, &status) == 0) {
		return status.st_size;
	} else {
		return -1;
	}
}

/* Combine two strings to one with a '/' in the middle.
 */
char *make_path(char *dir, char *file) {
	char *path;

	if ((dir == NULL) || (file == NULL)) {
		return NULL;
	}

	if ((path = (char*)malloc(strlen(dir) + strlen(file) + 2)) != NULL) {
		sprintf(path, "%s/%s", dir, file);
	}

	return path;
}

static t_fs_bool outside_webroot(char *symlink, char *webroot) {
	char filename[257], *slash;
	int size, count;

	if ((symlink == NULL) || (webroot == NULL)) {
		return fb_error;
	}

	if ((size = readlink(symlink, filename, 256)) > 0) {
		filename[size] = '\0';
		if (strchr(filename, '/') == NULL) {
			return fb_no;
		}
		if (filename[0] == '/') {
			/* Symlink with complete path */
			if (strncmp(webroot, filename, strlen(webroot)) == 0) {
				return fb_no;
			}
		} else if (strncmp(filename, "../", 3) == 0) {
			/* Symlink that starts wih ../ */
			count = 0;
			while (strncmp(filename + (3 * count), "../", 3) == 0) {
				count++;
			}
			slash = symlink + strlen(symlink);
			while (count-- > 0) {
				while ((slash > symlink) && (*slash != '/')) {
					slash--;
				}
				if (slash == symlink) {
					break;
				} else {
					slash--;
				}
			}
			if ((size_t)(slash - symlink) >= strlen(webroot)) {
				return fb_no;
			}
		}
	} else switch (errno) {
		case EACCES:
			return fb_no_access;
		case ENOENT:
			return fb_not_found;
		default:
			return fb_error;
	}

	return fb_yes;
}

t_fs_bool contains_not_allowed_symlink(char *filename, char *webroot) {
	t_fs_bool contains = fb_no, outside;
	struct stat status;
	char *slash;

	if ((filename == NULL) || (webroot == NULL)) {
		return fb_error;
	}

	if (lstat(filename, &status) == -1) {
		switch (errno) {
			case EACCES:
				return fb_no_access;
			case ENOENT:
				return fb_not_found;
			default:
				return fb_error;
		}
	} else if (((status.st_mode & S_IFMT) == S_IFLNK) && (status.st_uid != 0)) {
		if ((outside = outside_webroot(filename, webroot)) != fb_no) {
			return outside;
		}
	}

	slash = filename + strlen(filename);
	while ((slash != filename) && (*slash != '/')) {
		slash--;
	}
	if (slash != filename) {
		*slash = '\0';
		contains = contains_not_allowed_symlink(filename, webroot);
		*slash = '/';
	}

	return contains;
}

/* Check whether a file can be executed or not.
 */
t_fs_bool can_execute(char *file, uid_t uid, gid_t gid, t_groups *groups) {
	struct stat status;
	gid_t *group;
	int num = 0;

	if ((file == NULL) || (groups == NULL)) {
		return fb_error;
	}

	if (stat(file, &status) == 0) {
		if (status.st_uid == uid) {
			/* Check user */
			if ((status.st_mode & S_IXUSR) == S_IXUSR) {
				return fb_yes;
			} else {
				return fb_no;
			}
		} else {
			/* Check group */
			if (status.st_gid == gid) {
				if ((status.st_mode & S_IXGRP) == S_IXGRP) {
					return fb_yes;
				} else {
					return fb_no;
				}
			} else if (groups != NULL) {
				group = groups->array;
				while (num < groups->number) {
					if (status.st_gid == *group) {
						if ((status.st_mode & S_IXGRP) == S_IXGRP) {
							return fb_yes;
						} else {
							return fb_no;
						}
					}
					group++;
					num++;
				}
			}

			/* Check others */
			if ((status.st_mode & S_IXOTH) == S_IXOTH) {
				return fb_yes;
			} else {
				return fb_no;
			}
		}
	} else switch (errno) {
		case EACCES:
			return fb_no_access;
		case ENOENT:
			return fb_not_found;
		default:
			return fb_error;
	}
}

/* Check the type of a file (regular, directory, other)
 */
t_fs_type file_type(char *file) {
	struct stat status;

	if (file == NULL) {
		return ft_error;
	}

	if (stat(file, &status) == -1) {
		switch (errno) {
			case EACCES: return ft_no_access;
			case ENOENT: return ft_not_found;
			case ENOTDIR: return ft_file;
		}
		return ft_error;
	}

	if (S_ISREG(status.st_mode)) {
		return ft_file;
	}

	if (S_ISDIR(status.st_mode)) {
		return ft_dir;
	}

	return ft_other;
}

#ifndef CYGWIN
static int set_protection(char *file, struct stat *status, mode_t mode) {
	if ((status->st_mode & 07777) != mode) {
		if (chmod(file, mode) == -1) {
			return -1;
		}
	}

	return 0;
}

static int set_ownership(char *file, struct stat *status, uid_t uid, gid_t gid) {
	if ((status->st_uid != uid) || (status->st_gid != gid)) {
		if ((getuid() == 0) || (geteuid() == 0)) {
			if (chown(file, uid, gid) == -1) {
				return -1;
			}
		}
	}

	return 0;
}
#endif

/* Create a file with the right protection and ownership
 */
int create_file(char *file, mode_t mode, uid_t uid, gid_t gid) {
	struct stat status;
	int fd;

	if (file == NULL) {
		return -1;
	}

	if (strncmp(file, "/dev/", 5) == 0) {
		return 0;
	}

	if (stat(file, &status) == -1) {
		if (errno != ENOENT) {
			return -1;
		}
		if ((fd = open(file, O_CREAT, mode)) == -1) {
			return -2;
		}
		close(fd);

		if (stat(file, &status) == -1) {
			return -2;
		}
	}

#ifndef CYGWIN
	if (set_protection(file, &status, mode) == -1) {
		return -3;
	}

	if (set_ownership(file, &status, uid, gid) == -1) {
		return -4;
	}
#else
	/* prevent unused warning */
	(void)uid;
	(void)gid;
#endif

	return 0;
}

/* Create a directory with the right protection and ownership
 */
int create_directory(char *directory, mode_t mode, uid_t uid, gid_t gid) {
	struct stat status;

	if (stat(directory, &status) == -1) {
		if (errno != ENOENT) {
			return -1;
		} else if (mkdir(directory, mode) == -1) {
			return -2;
		}
	}

#ifndef CYGWIN
	if (set_protection(directory, &status, mode) == -1) {
		return -3;
	} else if (set_ownership(directory, &status, uid, gid) == -1) {
		return -4;
	}
#else
	/* prevent unused warning */
	(void)uid;
	(void)gid;
#endif

	return 0;
}

/* Remove files from directory
 */
int wipe_directory(char *directory, char *filter) {
	size_t dir_len, filter_len, name_len, file_len = 0, new_len;
	struct dirent *dir_info;
	char *file = NULL, *new;
	DIR *dp;
	int result = 0;

	if (directory == NULL) {
		return -1;
	}

	dir_len = strlen(directory);
	filter_len = (filter != NULL) ? strlen(filter) : 0;

	if ((dp = opendir(directory)) == NULL) {
		return -1;
	}

	while ((dir_info = readdir(dp)) != NULL) {
		if ((dir_info->d_name[0] == '.') || (strcmp(dir_info->d_name, "..") == 0)) {
			continue;
		}

		name_len = strlen(dir_info->d_name);

		if ((filter != NULL) && (name_len >= filter_len)) {
			if (strcmp(dir_info->d_name + name_len - filter_len, filter) != 0) {
				continue;
			}
		}

		new_len = dir_len + name_len + 102;
		if (new_len > file_len) {
			if ((new = (char*)realloc(file, new_len)) == NULL) {
				result = -1;
				break;
			}
			file = new;
			file_len = new_len;
		}

		sprintf(file, "%s/%s", directory, dir_info->d_name);
		if (file_type(file) == ft_file) {
			unlink(file);
		}
	}

	check_free(file);
	closedir(dp);

	return result;
}

/* Make gzipped duplicate of file
*/
int gzip_file(char *src, char *dest) {
	char buffer[8192];
	ssize_t bytes_read;
	int result = 0, f_in;
	gzFile f_out;

	if ((f_in = open(src, O_RDONLY)) == -1) {
		return -1;
	}

	if ((f_out = gzopen(dest, "w9")) == NULL) {
		return -1;
	}

	while ((bytes_read = read(f_in, buffer, 8192)) != 0) {
		if (bytes_read == -1) {
			if (errno == EINTR) {
				continue;
			}

			result = -1;
			break;
		}

		if (gzwrite(f_out, buffer, bytes_read) == -1) {
			result = -1;
			break;
		}
	}

	close(f_in);
	gzclose(f_out);

	if (result == -1) {
		unlink(dest);
	}

	return result;
}

/* Month number to month name.
 */
static short month2int(char *month) {
	int i;

	if (month != NULL) {
		for (i = 0; i < 12; i++) {
			if (memcmp(month, months[i], 3) == 0) {
				return i;
			}
		}
	}

	return -1;
}

/* Parse a RFC 822 datestring.
 *
 * 0    5  8   12   17       26
 * Day, dd Mon yyyy hh:mm:ss GMT
 */
static int parse_datestr(char *org_datestr, struct tm *date) {
	int result = -1;
	char *datestr;

	if ((org_datestr == NULL) || (date == NULL)) {
		return -1;
	} else if (strlen(org_datestr) != 29) {
		return -1;
	} else if ((datestr = strdup(org_datestr)) == NULL) {
		return -1;
	}

	if (memcmp(datestr + 3, ", ", 2) != 0) {
		goto parse_fail;
	} else if ((*(datestr + 7) != ' ') || (*(datestr + 11) != ' ') || (*(datestr + 16) != ' ')) {
		goto parse_fail;
	} else if ((*(datestr + 19) != ':') || (*(datestr + 22) != ':')) {
		goto parse_fail;
	} else if (memcmp(datestr + 25, " GMT", 4) != 0) {
		goto parse_fail;
	}

	*(datestr + 7) = *(datestr + 11) = *(datestr + 16) = *(datestr + 19) = *(datestr + 22) = *(datestr + 25) = '\0';
	if ((*datestr + 5) == ' ') {
		*(datestr + 5) = '0';
	}

	if ((date->tm_mday = str_to_int(datestr + 5)) <= 0) {
		goto parse_fail;
	} else if ((date->tm_mon = month2int(datestr + 8)) == -1) {
		goto parse_fail;
	} else if ((date->tm_year = str_to_int(datestr + 12)) < 1900) {
		goto parse_fail;
	} else if ((date->tm_hour = str_to_int(datestr + 17)) == -1) {
		goto parse_fail;
	} else if ((date->tm_min = str_to_int(datestr + 20)) == -1) {
		goto parse_fail;
	} else if ((date->tm_sec = str_to_int(datestr + 23)) == -1) {
		goto parse_fail;
	}

	if (date->tm_mday > 31) {
		goto parse_fail;
	} else if (date->tm_hour > 23) {
		goto parse_fail;
	} else if (date->tm_min > 59) {
		goto parse_fail;
	} else if (date->tm_sec > 59) {
		goto parse_fail;
	}

	date->tm_year -= 1900;
	date->tm_isdst = 0;

	result = 0;

parse_fail:
	free(datestr);

	return result;
}

/* Check wheter a file has been modified since a certain date or not.
 */
int if_modified_since(char *file, char *datestr) {
	struct stat status;
	struct tm date;
	time_t file_date, req_date;

	if (datestr == NULL) {
		return -1;
	} else if (stat(file, &status) == -1) {
		return -1;
	} else if (gmtime_r(&(status.st_mtime), &date) == NULL) {
		return -1;
	} else if ((file_date = mktime(&date)) == -1) {
		return -1;
	} else if (parse_datestr(datestr, &date) == -1) {
		return -1;
	} else if ((req_date = mktime(&date)) == -1) {
		return -1;
	} else if (file_date > req_date) {
		return 1;
	}

	return 0;
}

/* Open a file (searches in directory where file 'neighbour' is located if not found).
 */
FILE *fopen_neighbour(char *filename, char *mode, char *neighbour) {
	FILE *fp;
	char *file, *slash;
	int len_nb, len_fn;

	if ((filename == NULL) || (mode == NULL)) {
		return NULL;
	}

	if ((fp = fopen(filename, mode)) != NULL) {
		return fp;
	} else if ((errno != ENOENT) || (neighbour == NULL)) {
		return NULL;
	}

	if ((slash = strrchr(neighbour, '/')) == NULL) {
		return NULL;
	}

	len_nb = slash - neighbour + 1;
	len_fn = strlen(filename);
	if ((file = (char*)malloc(len_nb + len_fn + 1)) == NULL) {
		return NULL;
	}

	memcpy(file, neighbour, len_nb);
	strncpy(file + len_nb, filename, len_fn + 1);
	fp = fopen(file, mode);
	free(file);

	return fp;
}

/*-----< filelist functions >-------------------------------------------------*/

/* Read a directory and place the filenames in a list.
 */
t_filelist *read_filelist(char *directory, bool include_hidden_files) {
	DIR *dp;
	t_filelist *filelist = NULL, *file;
	char *filename;
	int stat_status;
	struct stat status;
	struct dirent *dir_info;

	if (directory == NULL) {
		return NULL;
	} else if ((dp = opendir(directory)) == NULL) {
		return NULL;
	}

	while ((dir_info = readdir(dp)) != NULL) {
		if (strcmp(dir_info->d_name, ".") == 0) {
			continue;
		}

		if (strcmp(dir_info->d_name, "..") != 0) {
			if ((dir_info->d_name[0] == '.') && (include_hidden_files == false)) {
				continue;
			}
		}

		if ((filename = make_path(directory, dir_info->d_name)) == NULL) {
			remove_filelist(filelist);
			filelist = NULL;
			break;
		}
		stat_status = stat(filename, &status);
		free(filename);
		if (stat_status == -1) {
			continue;
		}

		if ((file = (t_filelist*)malloc(sizeof(t_filelist))) == NULL) {
			remove_filelist(filelist);
			filelist = NULL;
			break;
		} else if ((file->name = strdup(dir_info->d_name)) == NULL) {
			free(file);
			remove_filelist(filelist);
			filelist = NULL;
			break;
		} else {
			file->size = status.st_size;
			file->time = status.st_mtime;
			file->is_dir = S_ISDIR(status.st_mode);
			file->next = filelist;
		}
		filelist = file;
	}
	closedir(dp);

	return filelist;
}

/* Sort a list of filenames alfabeticly.
 */
t_filelist *sort_filelist(t_filelist *filelist) {
	t_filelist *start = NULL, *newpos, *prev, *newitem;

	while (filelist != NULL) {
		newitem = filelist;
		filelist = filelist->next;

		prev = NULL;
		newpos = start;
		while (newpos != NULL) {
			if (newitem->is_dir && (newpos->is_dir == false)) {
				break;
			}
			if (newitem->is_dir == newpos->is_dir) {
				if (strcasecmp(newpos->name, newitem->name) >= 0) {
					break;
				}
			}
			prev = newpos;
			newpos = newpos->next;
		}

		if (prev == NULL) {
			newitem->next = start;
			start = newitem;
		} else {
			prev->next = newitem;
			newitem->next = newpos;
		}
	}

	return start;
}

/* free() a list of filenames.
 */
void remove_filelist(t_filelist *filelist) {
	t_filelist *file;

	while (filelist != NULL) {
		file = filelist;
		filelist = filelist->next;
		if (file->name != NULL) {
			free(file->name);
		}
		free(file);
	}
}

/* Send buffer to handle
 */
int write_buffer(int handle, const char *buffer, long size) {
	long total_written = 0;
	ssize_t bytes_written;

	if (size <= 0) {
		return 0;
	} else while (total_written < size) {
		if ((bytes_written = write(handle, buffer + total_written, size - total_written)) == -1) {
			if (errno != EINTR) {
				return -1;
			}
		} else {
			total_written += bytes_written;
		}
	}

	return 0;
}

#ifdef CYGWIN
char *cygwin_to_windows(char *path) {
	char *slash;

	if (path == NULL) {
		return NULL;
	}

	if (strncmp(path, "/cygdrive/", 10) != 0) {
		return path;
	}
	if (*(path + 10) == '\0') {
		return path;
	}
	if (*(path + 11) != '/') {
		return path;
	}

	path += 9;
	*path = *(path + 1);
	*(path + 1) = ':';

	slash = path;
	while (*slash != '\0') {
		if (*slash == '/') {
			*slash = '\\';
		}
		slash++;
	}

	return path;
}
#endif

int connect_to_unix_socket(char *unix_socket) {
	struct sockaddr_un sunix;
	int sock;

	if (strlen(unix_socket) >= sizeof(sunix.sun_path)) {
		return -1;
	}

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) != -1) {
		sunix.sun_family = AF_UNIX;
		strcpy(sunix.sun_path, unix_socket);
		if (connect(sock, (struct sockaddr*)&sunix, sizeof(struct sockaddr_un)) != 0) {
			close(sock);
			sock = -1;
		}
	}

	return sock;
}
