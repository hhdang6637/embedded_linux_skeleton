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

#ifndef _FILEHASHES_H
#define _FILEHASHES_H

#include "global.h"

#ifdef ENABLE_FILEHASHES

#define SHA_HASH_SIZE 32
#define FILE_HASH_SIZE SHA_HASH_SIZE * 2

typedef struct type_file_hash {
	char *filename;
	size_t filename_len;
	unsigned char hash[SHA_HASH_SIZE + 1];

	struct type_file_hash *next;
} t_file_hash;

t_file_hash *read_file_hashes(char *hashes_file);
bool file_hash_match(char *filename, t_file_hash *file_hash);
int print_file_hashes(char *directory);

#endif

#endif
