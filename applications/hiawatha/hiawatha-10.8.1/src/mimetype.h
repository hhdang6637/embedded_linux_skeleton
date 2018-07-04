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

#ifndef _MIMETYPE_H
#define _MIMETYPE_H

#include <stdbool.h>

typedef struct type_mimename {
    char *name;

    struct type_mimename *next;
} t_mimename;

typedef struct type_extension {
    char *name;
    struct type_mimename *mimename;

    struct type_extension *next;
} t_extension;

typedef struct type_mime {
	t_mimename  *mimename;
    t_extension *extension;
} t_mimetype;

int  read_mimetypes(char *configfile, t_mimetype **mime, bool config_check);
char *get_mimetype(char *extension, t_mimetype *mime);

#endif
