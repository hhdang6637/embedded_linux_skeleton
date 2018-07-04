#include "config.h"

#ifdef ENABLE_MEMDBG

#define MAXIMUM_LINES  10
#define CHARS_PER_LINE 16

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

typedef struct type_alloc_log {
	void *ptr;
	size_t size;
	char *filename;
	int  line_nr;
	pthread_t pthread_id;

	struct type_alloc_log *next;
} t_alloc_log;

static t_alloc_log *alloc_log = NULL;
static pthread_mutex_t alloc_log_mutex;

/* Initialize memory debug module
 */
int init_memdbg(void) {
	if (pthread_mutex_init(&alloc_log_mutex, NULL) != 0) {
		return -1;
	}

	fprintf(stderr, "Hiawatha v%s MemDbg module activated.\n", VERSION);

	return 0;
}

/* Log memory allocation
 */
static void log_alloc(void *ptr, size_t size, char *filename, int line_nr) {
	t_alloc_log *log;

	pthread_mutex_lock(&alloc_log_mutex);

	if ((log = malloc(sizeof(t_alloc_log))) != NULL) {
		log->ptr = ptr;
		log->size = size;
		log->filename = strdup(filename);
		log->line_nr = line_nr;
		log->pthread_id = pthread_self();
		log->next = alloc_log;
		alloc_log = log;
	}

	pthread_mutex_unlock(&alloc_log_mutex);
}

/* Log freeing of memory
 */
static void log_free(void *ptr, char *filename, int line_nr) {
	t_alloc_log *log, *prev = NULL;

	pthread_mutex_lock(&alloc_log_mutex);

	log = alloc_log;
	while (log != NULL) {
		if (log->ptr == ptr) {
			if (prev == NULL) {
				alloc_log = alloc_log->next;
			} else {
				prev->next = log->next;
			}
			if (log->filename != NULL) {
				free(log->filename);
			}
			free(log);
			break;
		}

		prev = log;
		log = log->next;
	}

	if (log == NULL) {
		fprintf(stderr, "Freeing unallocated memory at %s line %d.\n", filename, line_nr);
	}

	pthread_mutex_unlock(&alloc_log_mutex);
}

/* Clear memory allocation log
 */
void memdbg_clear_log(void) {
	t_alloc_log *log;

	pthread_mutex_lock(&alloc_log_mutex);

	while (alloc_log != NULL) {
		log = alloc_log;
		alloc_log = alloc_log->next;

		if (log->filename != NULL) {
			free(log->filename);
		}
		free(log);
	}

	pthread_mutex_unlock(&alloc_log_mutex);
}

/* Allocate memory
 */
void *memdbg_malloc(size_t size, char *filename, int line_nr) {
	void *result;

	if ((result = malloc(size)) != NULL) {
		log_alloc(result, size, filename, line_nr);
	}

	return result;
}

/* Re-allocate memory
 */
void *memdbg_realloc(void *ptr, size_t size, char *filename, int line_nr) {
	void *result;

	if (ptr != NULL) {
		log_free(ptr, filename, line_nr);
	}
	if ((result = realloc(ptr, size)) != NULL) {
		log_alloc(result, size, filename, line_nr);
	}

	return result;
}

/* Allocate multiple memory blocks
 */
void *memdbg_calloc(size_t nmemb, size_t size, char *filename, int line_nr) {
	void *result;

	if ((result = calloc(nmemb, size)) != NULL) {
		log_alloc(result, nmemb * size, filename, line_nr);
	}

	return result;
}

/* Duplicate string
 */
char *memdbg_strdup(char *str, char *filename, int line_nr) {
	char *result;

	if ((result = strdup(str)) != NULL) {
		log_alloc(result, strlen(result), filename, line_nr);
	}

	return result;
}

/* Duplicate some bytes of string
 */
char *memdbg_strndup(char *str, size_t size, char *filename, int line_nr) {
	char *result;

	if ((result = strndup(str, size)) != NULL) {
		log_alloc(result, size, filename, line_nr);
	}

	return result;
}

/* Free memory
 */
void memdbg_free(void *ptr, char *filename, int line_nr) {
	log_free(ptr, filename, line_nr);
	free(ptr);
}

/* Print memory allocations
 */
void memdbg_print_log(bool print_all) {
	t_alloc_log *log;
	pthread_t self;
	unsigned char c;
	size_t line, i, max_line, max_i, total = 0;

	self = pthread_self();

	pthread_mutex_lock(&alloc_log_mutex);

	fprintf(stderr, "--[ %c ]--------------------------\n", print_all ? 'A' : 'T');

	log = alloc_log;
	while (log != NULL) {
		if (print_all == false) {
			if (pthread_equal(log->pthread_id, self) == 0) {
				log = log->next;
				continue;
			}
		} else {
			total += log->size;
		}

		if (log->filename != NULL) {
			fprintf(stderr, "Filename:    %s\n", log->filename);
		}
		fprintf(stderr, "Line number: %d\n", log->line_nr);
		fprintf(stderr, "Memory size: %ld\n", (long)log->size);

		if ((max_line = log->size) > MAXIMUM_LINES * CHARS_PER_LINE) {
			max_line = MAXIMUM_LINES * CHARS_PER_LINE;
		}
		for (line = 0; line < max_line; line += CHARS_PER_LINE) {
			if ((max_i = log->size - line) > CHARS_PER_LINE) {
				max_i = CHARS_PER_LINE;
			}

			for (i = 0; i < max_i; i++) {
				fprintf(stderr, "%02X ", *((unsigned char*)log->ptr + line + i));
			}
			for (i = max_i; i < CHARS_PER_LINE; i++) {
				fprintf(stderr, "   ");
			}

			fprintf(stderr, "  |");
			for (i = 0; i < max_i; i++) {
				c = *((unsigned char*)log->ptr + line + i);
				if ((c >= 32) && (c <= 126)) {
					fprintf(stderr, "%c", c);
				} else {
					fprintf(stderr, ".");
				}
			}
			for (i = max_i; i < CHARS_PER_LINE; i++) {
				fprintf(stderr, " ");
			}

			fprintf(stderr, "|\n");
		}

		fprintf(stderr, "\n");

		log = log->next;
	}

	if (print_all) {
		fprintf(stderr, "Total memory usage: %ld\n\n", (long)total);
	}

	pthread_mutex_unlock(&alloc_log_mutex);
}

#endif
