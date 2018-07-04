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

#ifndef _USERCONFIG_H
#define _USERCONFIG_H

#include <sys/types.h>

typedef struct type_groups {
	int   number;
	gid_t *array;
} t_groups;

void init_groups(t_groups *groups);
int  parse_userid(char *userid, uid_t *uid);
int  parse_groups(char *groupid, gid_t *gid, t_groups *groups);
int  lookup_group_ids(uid_t uid, gid_t *gid, t_groups *groups);

#endif
