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
#include <string.h>
#include "libstr.h"
#include "mimetype.h"
#include "memdbg.h"

#define MAX_LINE_LENGTH 256
#define MAX_EXT_LEN      16

static char *default_mimetype = "application/octet-stream";

/* Read a mimetype configuration file.
 */
int read_mimetypes(char *configfile, t_mimetype **mime, bool config_check) {
	FILE *fp;
	char line[MAX_LINE_LENGTH + 1], *data, *next, *ext;
	bool quit;
	t_mimename *w_mime = NULL;
	t_extension *w_ext = NULL;

	if (config_check) {
		printf("Reading %s\n", configfile);
	}

	/* Read mimetype configurationfile.
	 */
	if ((fp = fopen(configfile, "r")) == NULL) {
		return -1;
	}

	if ((*mime = (t_mimetype*)malloc(sizeof(t_mimetype))) == NULL) {
		fclose(fp);
		return -1;
	}
	(*mime)->mimename = NULL;
	(*mime)->extension = NULL;

	line[MAX_LINE_LENGTH] = '\0';

	while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
		if (line[0] == '#') {
			continue;
		}

		if ((next = data = strdup(line)) == NULL) {
			fclose(fp);
			return -1;
		}

		while (*next != '\0') {
			if (*next == '\t') {
				*next = ' ';
			} else if ((*next == '\r') || (*next == '\n')) {
				*next = '\0';
				break;
			} else if (*next == '#') {
				*next = '\0';
				break;
			}
			next++;
		}

		next = data;
		while ((*next == ' ') && (*next != '\0')) {
			next++;
		}
		if (*next == '\0') {
			free(data);
			continue;
		}
		data = next;

		if ((next = strchr(data, ' ')) != NULL) {
			*next++ = '\0';
			if (w_mime == NULL) {
				if (((*mime)->mimename = w_mime = (t_mimename*)malloc(sizeof(t_mimename))) == NULL) {
					fclose(fp);
					return -1;
				}
			} else {
				if ((w_mime->next = (t_mimename*)malloc(sizeof(t_mimename))) == NULL) {
					fclose(fp);
					return -1;
				}
				w_mime = w_mime->next;
			}
			w_mime->next = NULL;
			w_mime->name = data;

			quit = false;
			while (quit == false) {
				while (*next == ' ') {
					next++;
				}
				if (*next != '\0') {
					ext = next;
					if ((next = strchr(next, ' ')) != NULL) {
						*next++ = '\0';
					} else {
						quit = true;
					}
					if (strlen(ext) <= MAX_EXT_LEN) {
						if (w_ext == NULL) {
							if (((*mime)->extension = w_ext = (t_extension*)malloc(sizeof(t_extension))) == NULL) {
								fclose(fp);
								return -1;
							}
						} else {
							if ((w_ext->next = (t_extension*)malloc(sizeof(t_extension))) == NULL) {
								fclose(fp);
								return -1;
							}
							w_ext = w_ext->next;
						}
						w_ext->next = NULL;
						w_ext->mimename = w_mime;
						w_ext->name = ext;
						strlower(w_ext->name);
					}
				} else {
					quit = true;
				}
			}
		}
	}

	fclose(fp);

	return 0;
}

/* Return the mimetype of a file.
 */
char *get_mimetype(char *extension, t_mimetype *mime) {
	char *ext_lower, *result = default_mimetype;
	t_extension *w_ext = NULL;

	/* Convert file extension to mimetype.
	 */
	if ((extension == NULL) || (mime == NULL)) {
		return NULL;
	} else if ((ext_lower = strlower(strdup(extension))) == NULL) {
		return NULL;
	}

	w_ext = mime->extension;
	while (w_ext != NULL) {
		if (strcmp(ext_lower, w_ext->name) == 0) {
			result = w_ext->mimename->name;
			break;
		}
		w_ext = w_ext->next;
	}

	free(ext_lower);

	return result;
}
