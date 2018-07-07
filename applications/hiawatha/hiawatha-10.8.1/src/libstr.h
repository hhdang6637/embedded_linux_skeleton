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

#ifndef _LIBSTR_H
#define _LIBSTR_H

#include "config.h"
#include <sys/types.h>
#include <stdbool.h>
#include <regex.h>

#define CHECK_USE_STRLEN -1

void check_free(void *ptr);
void clear_free(void *ptr, int size);
void check_clear_free(void *ptr, int size);

int  parse_yesno(char *yesno, bool *result);
int  str_to_int(char *str);
int time_str_to_int(char *str);
bool empty_string(char *str);
short hex_char_to_int(char c);
int  hex_to_int(char *str);
char *remove_spaces(char *str);
char *uncomment(char *str);
char *strlower(char *str);
int  split_string(const char *str, char **key, char **value, char c);
int  split_configline(const char *str, char **key, char **value);
bool valid_uri(char *uri, bool allow_dot_files);
int  url_encode(char *str, char **encoded);
void url_decode(char *str);
bool forbidden_chars_present(char *str);
int  str_replace(char *src, char *from, char *to, char **dst);
bool min_strlen(char *str, int n);
int  header_to_variable(char *header, char *variable, int size);
int  filesize2str(char *buffer, int len, off_t fsize);
int  add_str(char **buffer, int *size, int extra_size, int *len, char *str);
int  strpcmp(char *str, regex_t *regexp);
int strcmp_rtap(const char *s1, const char *s2);
void md5_bin2hex(unsigned char bin[16], char hex[33]);
void sha256_bin2hex(unsigned char bin[32], char hex[65]);
bool hostname_match(char *hostname, char *pattern);
bool extension_from_uri(char *line, char *extension, size_t size);

#endif
