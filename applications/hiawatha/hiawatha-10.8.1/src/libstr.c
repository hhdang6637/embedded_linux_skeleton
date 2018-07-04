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
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <regex.h>
#include "global.h"
#include "alternative.h"
#include "libstr.h"
#include "memdbg.h"

#define MAX_DEC_VALUE (INT_MAX - 10) / 10
#define MAX_HEX_VALUE (INT_MAX - 16) / 16

/* Memory free functions
 */
void check_free(void *ptr) {
	if (ptr != NULL) {
		free(ptr);
	}
}

void clear_free(void *ptr, int size) {
	if (size == CHECK_USE_STRLEN) {
		size = strlen(ptr);
	}

	memset(ptr, 0, size);
	free(ptr);
}

void check_clear_free(void *ptr, int size) {
	if (ptr != NULL) {
		clear_free(ptr, size);
	}
}

/* Convert string to a boolean.
 */
int parse_yesno(char *yesno, bool *result) {
	if ((strcmp(yesno, "no") == 0) || (strcmp(yesno, "false") == 0)) {
		*result = false;
	} else if ((strcmp(yesno, "yes") == 0) || (strcmp(yesno, "true") == 0)) {
		*result = true;
	} else {
		return -1;
	}

	return 0;
}

/* Convert a string to an integer.
 */
int str_to_int(char *str) {
	int value = 0;

	if (str == NULL) {
		return -1;
	} else if (*str == '\0') {
		return -1;
	}

	do {
		if (value >= MAX_DEC_VALUE) {
			return -1;
		}
		if ((*str < '0') || (*str > '9')) {
			return -1;
		}
		value = (10 * value) + (*str - '0');
		str++;
	} while (*str != '\0');

	return value;
}

/* Convert a time string to an integer
 */
int time_str_to_int(char *str) {
	int value, mul;
	size_t len;

	if (str == NULL) {
		return -1;
	} else if ((len = strlen(str)) == 0) {
		return -1;
	}

	if (str[len - 1] == 'm') {
		mul = MINUTE;
		str[len - 1] = '\0';
	} else if (str[len - 1] == 'h') {
		mul = HOUR;
		str[len - 1] = '\0';
	} else if (str[len - 1] == 'd') {
		mul = DAY;
		str[len - 1] = '\0';
	} else {
		mul = 1;
	}

	if ((value = str_to_int(str)) == -1) {
		return -1;
	}

	if ((mul > 1) && (value > 3650)) {
		return -1;
	}

	return value * mul;
}

/* Check if string is empty
 */
bool empty_string(char *str) {
	if (str == NULL) {
		return true;
	}

	while (*str != '\0') {
		if ((*str != ' ') && (*str != '\t')) {
			return false;
		}
		str++;
	}

	return true;
}

/* Convert a hexadecimal char to decimal.
 */
short hex_char_to_int(char c) {
	 if ((c >= '0') && (c <= '9')) {
		 return c - '0';
	 } else if ((c >= 'A') && (c <= 'F')) {
		 return c - 'A' + 10;
	 } else if ((c >= 'a') && (c <= 'f')) {
		 return c - 'a' + 10;
	 }

	 return -1;
}

/* Convert a hexadecimal string to an integer.
 */
int hex_to_int(char *str) {
	int value = 0;
	short digit;

	if (str == NULL) {
		return -1;
	} else if (*str == '\0') {
		return -1;
	}

	do {
		if (value >= MAX_HEX_VALUE) {
			return -1;
		}
		if ((digit = hex_char_to_int(*str)) == -1) {
			return -1;
		}
		value = (16 * value) + digit;
		str++;
	} while (*str != '\0');

	return value;
}

/* Remove the leading and trailing spaces in a string.
 */
char *remove_spaces(char *str) {
	int pos;

	if (str != NULL) {
		while ((*str == ' ') || (*str == '\t')) {
			str++;
		}
		pos = strlen(str) - 1;
		while (pos >= 0) {
			switch (*(str + pos)) {
				case ' ':
				case '\t':
				case '\r':
				case '\n':
					*(str + pos) = '\0';
					pos--;
					break;
				default:
					pos = -1;
			}
		}
	}

	return str;
}

/* Remove comment from a string.
 */
char *uncomment(char *str) {
	char *hash;

	if (str == NULL) {
		return NULL;
	}

	if (*str == '#') {
		*str = '\0';
		return str;
	}

	if ((hash = strstr(str, " #")) != NULL) {
		*hash = '\0';
	}

	if ((hash = strstr(str, "\t#")) != NULL) {
		*hash = '\0';
	}

	return remove_spaces(str);
}

/* Covert a string to lowercase.
 */
char *strlower(char *str) {
	char *c;

	if (str != NULL) {
		c = str;
		while (*c != '\0') {
			if ((*c >= 'A') && (*c <= 'Z')) {
				*c += 32;
			}
			c++;
		}
	}

	return str;
}

/* Split a string in 2 strings.
 */
int split_string(const char *str, char **key, char **value, char c) {
	if ((str == NULL) || (key == NULL) || (value == NULL)) {
		return -1;
	}

	*key = (char*)str;
	if ((*value = strchr(*key, c)) == NULL) {
		return -1;
	}

	*(*value)++ = '\0';
	*key = remove_spaces(*key);
	*value = remove_spaces(*value);

	return 0;
}

int split_configline(const char *str, char **key, char **value) {
	int eq = 0;

	if ((str == NULL) || (key == NULL) || (value == NULL)) {
		return -1;
	}

	*key = remove_spaces((char*)str);
	*value = *key;

	while (**value != '\0') {
		if ((**value == ' ') || (**value == '=')) {
			if (**value == '=') {
				eq++;
			}
			**value = '\0';

			do {
				(*value)++;
				if (**value == '=') {
					eq++;
				}
			} while ((**value == ' ') || (**value == '='));

			return (eq > 1) ? -1 : 0;
		}

		(*value)++;
	}

	return -1;
}

/* Check the validity of an URL.
 */
bool valid_uri(char *uri, bool allow_dot_files) {
	char *pos;
	size_t size;
#ifdef CYGWIN
	size_t last_pos;
#endif

	if (uri == NULL) {
		return false;
	} else if (*uri != '/') {
		return false;
	}

	size = strlen(uri);

	if (allow_dot_files && (size >= 10)) {
		if (strcmp(uri + size - 10, "/.hiawatha") == 0) {
			return false;
		}
#ifdef CYGWIN
		if (strcmp(uri + size - 10, "\\.hiawatha") == 0) {
			return false;
		}
#endif
	}

#ifdef CYGWIN
	/* Deny trailing dots and spaces */
	last_pos = size - 1;
	if (*(uri + last_pos) == '.') {
		return false;
	} else if (*(uri + last_pos) == ' ') {
		return false;
	}

	/* Deny 8.3 file format */
	if (last_pos >= 6) {
		if ((*(uri + last_pos - 5) == '~') && (*(uri + last_pos - 4) >= '0') &&
			(*(uri + last_pos - 4) <= '9') && (*(uri + last_pos - 3) == '.')) {
			return false;
		}
	}

	if ((pos = strstr(uri, "\\.")) != NULL) {
		if ((allow_dot_files == false) || (*(pos + 2) == '.')) {
			return false;
		}
	}
#endif

	/* RFC 5785 */
	if (strncmp(uri, "/.well-known", 12) != 0) {
		pos = uri;
	} else if (*(uri + 12) == '/') {
		pos = uri + 12;
	} else {
		return *(uri + 12) == '\0';
	}

	if ((pos = strstr(pos, "/.")) != NULL) {
		if ((allow_dot_files == false) || (*(pos + 2) == '.')) {
			return false;
		}
	}

	while (*(++uri) != '\0') {
		if ((unsigned char)*uri < 32) {
			return false;
		}
	}

	return true;
}

/* Encode a string to an URL encoded one
 */
static bool char_needs_encoding(char c) {
	return (c <= 32) || (strchr("\"#\%&'+:<>?", c) != NULL) || (c >= 126);
}
int url_encode(char *str, char **encoded) {
	char *c, *e;
	int replaced = 0;

	if (str == NULL) {
		return -1;
	}

	c = str;
	while (*c != '\0') {
		if (char_needs_encoding(*c)) {
			replaced++;
		}
		c++;
	}

	if (replaced == 0) {
		*encoded = NULL;
		return 0;
	} else if ((*encoded = (char*)malloc(strlen(str) + (2 * replaced) + 1)) == NULL) {
		return -1;
	}

	c = str;
	e = *encoded;
	while (*c != '\0') {
		if (char_needs_encoding(*c)) {
			sprintf(e, "%%%02hhx", *c);
			e += 2;
		} else {
			*e = *c;
		}
		c++;
		e++;
	}
	*e = '\0';

	return replaced;
}

/* Decode the URL encoded characters (%XX).
 */
void url_decode(char *str) {
	short low, high;
	char *dest = str;

	if (str == NULL) {
		return;
	}

	while (*str != '\0') {
		if (*str == '%') {
			if ((high = hex_char_to_int(*(str + 1))) != -1) {
				if ((low = hex_char_to_int(*(str + 2))) != -1) {
					str += 2;
					*str = (char)(high<<4) + low;
				}
			}
		}
		*(dest++) = *(str++);
	}

	*dest = '\0';
}

/* Scan for characters with ASCII value < 32.
 */
bool forbidden_chars_present(char *str) {
	short low, high;

	if (str == NULL) {
		return false;
	}

	while (*str != '\0') {
		if ((*str > 0) && (*str < 32)) {
			return true;
		} else if (*str == '%') {
			if ((high = hex_char_to_int(*(str + 1))) != -1) {
				if ((low = hex_char_to_int(*(str + 2))) != -1) {
					if (((high << 4) + low) < 32) {
						return true;
					}
				}
			}
		}
		str++;
	}

	return false;
}

int str_replace(char *src, char *from, char *to, char **dst) {
	char *pos, *start;
	int replaced = 0, len_from, len_to, len_start;

	if ((src == NULL) || (from == NULL) || (to == NULL) || (dst == NULL)) {
		return 0;
	}

	if ((len_from = strlen(from)) == 0) {
		return -1;
	}
	len_to = strlen(to);

	start = src;
	while ((pos = strstr(start, from)) != NULL) {
		if ((*dst = (char*)malloc(strlen(src) - len_from + len_to + 1)) == NULL) {
			if (replaced > 0) {
				free(src);
			}
			return -1;
		}
		len_start = pos - src;
		memcpy(*dst, src, len_start);
		if (len_to > 0) {
			memcpy(*dst + len_start, to, len_to);
		}
		strcpy(*dst + len_start + len_to, pos + len_from);

		if (replaced > 0) {
			free(src);
		}
		if (replaced++ == 100) {
			if (*dst != NULL) {
				free(*dst);
			}
			return -1;
		}
		src = *dst;
		start = src + len_start + len_to;
	}

	return replaced;
}

bool min_strlen(char *str, int n) {
	int i = 0;

	if (str != NULL) {
		while (i < n) {
			if (*(str + i) == '\0') {
				return false;
			}
			i++;
		}
	}

	return true;
}

int header_to_variable(char *header, char *variable, int size) {
	char *column;
	int len, i;

	if ((column = strchr(header, ':')) == NULL) {
		return -1;
	}
	len = column - header;
	if (len + 6 > size) {
		return -1;
	}

	strcpy(variable, "HTTP_");

	for (i = 0; i < len; i++) {
		if (((header[i] >= 'A') && (header[i] <= 'Z')) || ((header[i] >= '0') && (header[i] <= '9'))) {
			variable[i + 5] = header[i];
		} else if ((header[i] >= 'a') && (header[i] <= 'z')) {
			variable[i + 5] = header[i] - 32;
		} else if (header[i] == '-') {
			variable[i + 5] = '_';
		} else {
			return -1;
		}
	}
	variable[len + 5] = '\0';

	return 0;
}

/* Converts a filesize to a string.
 */
int filesize2str(char *buffer, int len, off_t fsize) {
	int result = 0;

	if (fsize < KILOBYTE) {
		result = snprintf(buffer, len - 1, "%llu byte", (long long)fsize);
	} else if (fsize < MEGABYTE) {
		result = snprintf(buffer, len - 1, "%0.1f kB", ((double)(fsize >> 6)) / 16);
	} else if (fsize < GIGABYTE) {
		result = snprintf(buffer, len - 1, "%0.1f MB", ((double)(fsize >> 16)) / 16);
	} else {
		result = snprintf(buffer, len - 1, "%0.1f GB", ((double)(fsize >> 26)) / 16);
	}
	buffer[len - 1] = '\0';

	if (result == -1) {
		return -1;
	} else if (result >= len) {
		return -1;
	}

	return result;
}

/* Add 'str' with length 'len' to 'buffer' with size 'size'. If it does not
 * fit, expand buffer with 'extra_size' bytes.
 */
int add_str(char **buffer, int *size, int extra_size, int *len, char *str) {
	size_t str_len;
	char *new;

	str_len = strlen(str);
	while (*len + (int)str_len >= *size) {
		*size += extra_size;
		if ((new = (char*)realloc(*buffer, *size)) == NULL) {
			*size -= extra_size;
			return -1;
		}
		*buffer = new;
	}

	memcpy(*buffer + *len, str, str_len);
	*len += str_len;
	*(*buffer + *len) = '\0';

	return 0;
}

int strpcmp(char *str, regex_t *regexp) {
	return (regexec(regexp, str, 0, NULL, 0) == 0) ? 0 : -1;
}

/* strcmp with remote timing-attack prevention
 */
int strcmp_rtap(const char *s1, const char *s2) {
	size_t l1, l2, len = 0, extra = 0, i;
	int result = 0;

	if ((s1 == NULL) || (s2 == NULL)) {
		return -1;
	}

	l1 = strlen(s1);
	l2 = strlen(s2);

	if (l1 < l2) {
		result = 1;
		len = l1;
		extra = 0;
	}
	if (l1 > l2) {
		result = 1;
		len = l2;
		extra = l1 - l2;
	}
	if (l1 == l2) {
		result = 0;
		len = l1;
		extra = 0;
	}

	for (i = 0; i < len; i++) {
		result |= s1[i] ^ s2[i];
	}

	for (i = 0; i < extra; i++) {
		result |= s1[i] ^ s2[0];
	}

	return result;
}

void md5_bin2hex(unsigned char bin[16], char hex[33]) {
	int i;

	for (i = 0; i < 16; i++) {
		sprintf(&hex[2 * i], "%02x", bin[i]);
	}
	hex[32] = '\0';
}

void sha256_bin2hex(unsigned char bin[32], char hex[65]) {
	int i;

	for (i = 0; i < 32; i++) {
		sprintf(&hex[2 * i], "%02x", bin[i]);
	}
	hex[64] = '\0';
}

bool hostname_match(char *hostname, char *pattern) {
	size_t len, len_hostname;

	if ((len_hostname = strlen(hostname)) == 0) {
		return false;
	}

	if (strcmp(hostname, pattern) == 0) {
		/* Exact match
		 */
		return true;
	} else if (strncmp(pattern, "*.", 2) == 0) {
		/* Wildcard in configuration
		 */
		if (strcmp(hostname, pattern + 2) == 0) {
			/* Only domainname requested
			 */
			return true;
		} else {
			len = strlen(pattern);
			if (len_hostname >= len) {
				if (strcmp(hostname + len_hostname - len + 1, pattern + 1) == 0) {
					/* Wildcard match for hostname
					 */
					return true;
				}
			}
		}
	}

	return false;
}

bool extension_from_uri(char *line, char *extension, size_t size) {
	char *c, *dot = NULL, *qmark = NULL;
	size_t len;

	if ((line == NULL) || (extension == NULL)) {
		return false;
	}

	c = line;
	while (*c != '\0') {
		if (*c == '?') {
			qmark = c;
			break;
		} else if (*c == '.') {
			dot = c + 1;
		}
		c++;
	}

	if (dot == NULL) {
		return false;
	} else if (qmark == NULL) {
		len = strlen(dot);
	} else {
		len = qmark - dot;
	}

	if (len >= size) {
		return false;
	}

	memcpy(extension, dot, len);
	*(extension + len) = '\0';

	return true;
}
