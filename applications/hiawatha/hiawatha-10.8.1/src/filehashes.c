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

#ifdef ENABLE_FILEHASHES

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include "global.h"
#include "libstr.h"
#include "libfs.h"
#include "filehashes.h"
#include "mbedtls/sha256.h"
#include "memdbg.h"

#define BUFFER_SIZE 1024

int sha256_file(const char *path, unsigned char output[32], int is224) {
	FILE *fp;
	size_t bytes_read;
	mbedtls_sha256_context context;
	unsigned char buffer[BUFFER_SIZE];

	if ((fp = fopen(path, "rb")) == NULL) {
		return -1;
	}

	mbedtls_sha256_init(&context);
	mbedtls_sha256_starts(&context, is224);

	while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
		mbedtls_sha256_update(&context, buffer, bytes_read);
	}

	mbedtls_sha256_finish(&context, output);
	mbedtls_sha256_free(&context);

	if (ferror(fp) != 0) {
		fclose(fp);
		return -1;
	}

	fclose(fp);

	return 0;
}

t_file_hash *read_file_hashes(char *hashes_file) {
	FILE *fp;
	char line[1024], *filename, *hash;
	t_file_hash *file_hash = NULL, *new;

	if ((fp = fopen(hashes_file, "r")) == NULL) {
		return NULL;
	}

	while (fgets(line, 1023, fp) != NULL) {
		line[1023] = '\0';
		if (strlen(line) > 1020) {
			fclose(fp);
			return NULL;
		}

		if (split_string(line, &hash, &filename, ':') != 0) {
			fclose(fp);
			return NULL;
		}

		if ((new = (t_file_hash*)malloc(sizeof(t_file_hash))) == NULL) {
			fclose(fp);
			return NULL;
		}

		if (strlen(hash) != FILE_HASH_SIZE) {
			free(new);
			fclose(fp);
			return NULL;
		}
		memcpy(new->hash, hash, SHA_HASH_SIZE + 1);

		if ((new->filename = strdup(filename)) == NULL) {
			free(new);
			fclose(fp);
			return NULL;
		}
		new->filename_len = strlen(new->filename);

		new->next = file_hash;
		file_hash = new;
	}

	fclose(fp);

	return file_hash;
}

static int memrcmp(char *s1, char *s2, size_t len) {
	if (len == 0) {
		return 0;
	}

	s1 += (len - 1);
	s2 += (len - 1);

	do {
		if (*s1 != *s2) {
			return *s1 - *s2;
		}

		s1--;
		s2--;
		len--;
	} while (len > 0);

	return 0;
}

static t_file_hash *search_file(char *filename, t_file_hash *file_hashes) {
	size_t len;

	len = strlen(filename);
	while (file_hashes != NULL) {
		if (len == file_hashes->filename_len) {
			if (memrcmp(filename, file_hashes->filename, len) == 0) {
				return file_hashes;
			}
		}
		file_hashes = file_hashes->next;
	}

	return NULL;
}

bool file_hash_match(char *filename, t_file_hash *file_hashes) {
	t_file_hash *file_hash;
	unsigned char bin_hash[SHA_HASH_SIZE];
	char hex_hash[FILE_HASH_SIZE + 1];

	if ((file_hash = search_file(filename, file_hashes)) == NULL) {
		return false;
	}
	if (sha256_file(filename, bin_hash, 0) != 0) {
		return false;
	}
	sha256_bin2hex(bin_hash, hex_hash);

	if (memcmp(file_hash->hash, hex_hash, SHA_HASH_SIZE) != 0) {
		return false;
	}

	return true;
}

int print_file_hashes(char *directory) {
	DIR *dp;
	struct dirent *fileinfo;
	unsigned char bin_hash[SHA_HASH_SIZE];
	char hex_hash[FILE_HASH_SIZE + 1], *file = NULL;
	int result = -1;

	if ((dp = opendir(directory)) == NULL) {
		return -1;
	}

	while ((fileinfo = readdir(dp)) != NULL) {
		if (fileinfo->d_name[0] == '.') {
			continue;
		}

		if ((file = malloc(strlen(directory) + strlen(fileinfo->d_name) + 2)) == NULL) {
			goto hash_fail;
		}
		sprintf(file, "%s/%s", directory, fileinfo->d_name);

		switch (file_type(file)) {
			case ft_dir:
				if (print_file_hashes(file) == -1) {
					goto hash_fail;
				}
				break;
			case ft_file:
				if (sha256_file(file, bin_hash, 0) != 0) {
					goto hash_fail;
				}
				sha256_bin2hex(bin_hash, hex_hash);

				printf("%s : %s\n", hex_hash, file);
				break;
			default:
				break;
		}

		free(file);
		file = NULL;
	}

	result = 0;

hash_fail:
	closedir(dp);
	if (file != NULL) {
		free(file);
	}

	return result;
}

#endif
