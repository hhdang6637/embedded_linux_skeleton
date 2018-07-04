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
#include <stdbool.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include "libstr.h"
#include "userconfig.h"
#include "memdbg.h"

void init_groups(t_groups *groups) {
	groups->number = 0;
	groups->array = NULL;
}

int parse_userid(char *userid, uid_t *uid) {
	struct passwd *pwd;
	int id;

	if (userid == NULL) {
		return -1;
	}

	if ((id = str_to_int(userid)) == -1) {
		if ((pwd = getpwnam(userid)) == NULL) {
			return -1;
		}
		*uid = pwd->pw_uid;
	} else {
		*uid = id;
	}

	return (*uid == 0) ? 0 : 1;
}

static gid_t parse_groupid(char *groupid, gid_t *gid) {
	struct group *grp;
	int id;

	if (groupid == NULL) {
		return -1;
	}

	if ((id = str_to_int(groupid)) == -1) {
		if ((grp = getgrnam(groupid)) == NULL) {
			return -1;
		}
		*gid = grp->gr_gid;
	} else {
		*gid = id;
	}

	return (*gid == 0) ? 0 : 1;
}

int parse_groups(char *groupid, gid_t *gid, t_groups *groups) {
	int i, count = 0, result = 0;
	gid_t *id;
	char *c;

	if ((groupid == NULL) || (gid == NULL) || (groups == NULL)) {
		return -1;
	}

	c = groupid;
	while (*c != '\0') {
		if (*c == ',') {
			count++;
			*c = '\0';
		}
		c++;
	}

	if ((result = parse_groupid(groupid, gid)) == -1) {
		return -1;
	} else if ((groups->number = count) == 0) {
		return result;
	} else if ((groups->array = id = (gid_t*)malloc(groups->number * sizeof(gid_t))) == NULL) {
		return -1;
	}

	for (i = 0; i < count; i++) {
		groupid = groupid + strlen(groupid) + 1;
		switch (parse_groupid(groupid, id)) {
			case -1:
				free(groups->array);
				return -1;
			case 0:
				result = 0;
				break;
		}
		id++;
	}

	return result;
}

static bool is_member(char *user, char **group) {
	if ((user == NULL) || (group == NULL)) {
		return false;
	}

	while (*group != NULL) {
		if (strcmp(user, *group) == 0) {
			return true;
		}
		group++;
	}

	return false;
}

int lookup_group_ids(uid_t uid, gid_t *gid, t_groups *groups) {
	struct passwd *pwd;
	struct group *grp;
	int size, result;
	gid_t *id;

	if ((gid == NULL) || (groups == NULL)) {
		return -1;
	} else if ((pwd = getpwuid(uid)) == NULL) {
		return -1;
	}

	if ((*gid = pwd->pw_gid) == 0) {
		result = 0;
	} else {
		result = 1;
	}

	groups->number = size = 0;
	groups->array = NULL;
	while ((grp = getgrent()) != NULL) {
		if (is_member(pwd->pw_name, grp->gr_mem)) {
			if (grp->gr_gid == 0) {
				result = 0;
			}
			if (groups->number == size) {
				size += 10;
				if ((id = realloc(groups->array, size * sizeof(gid_t))) == NULL) {
					free(groups->array);
					endgrent();
					return -1;
				}
				groups->array = id;
			}
			*(groups->array + groups->number) = grp->gr_gid;
			groups->number++;
		}
	}
	endgrent();

	return result;
}
