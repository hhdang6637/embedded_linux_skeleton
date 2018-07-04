#ifndef _MEMDBG_H
#define _MEMDBG_H

#include "config.h"

#ifdef ENABLE_MEMDBG

#include <stdbool.h>

#ifdef malloc
#undef malloc
#endif
#define malloc(size) memdbg_malloc(size, __FILE__, __LINE__)

#ifdef realloc
#undef realloc
#endif
#define realloc(ptr, size) memdbg_realloc(ptr, size, __FILE__, __LINE__)

#ifdef calloc
#undef calloc
#endif
#define calloc(nmemb, size) memdbg_calloc(nmemb, size, __FILE__, __LINE__)

#ifdef strdup
#undef strdup
#endif
#define strdup(str) memdbg_strdup(str, __FILE__, __LINE__)

#ifdef strndup
#undef strndup
#endif
#define strndup(str, size) memdbg_strndup(str, size, __FILE__, __LINE__)

#ifdef free
#undef free
#endif
#define free(ptr) memdbg_free(ptr, __FILE__, __LINE__)

int init_memdbg(void);
void memdbg_clear_log(void);
void *memdbg_malloc(size_t size, char *filename, int line_nr);
void *memdbg_realloc(void *ptr, size_t size, char *filename, int line_nr);
void *memdbg_calloc(size_t nmemb, size_t size, char *filename, int line_nr);
char *memdbg_strdup(const char *str, char *filename, int line_nr);
char *memdbg_strndup(const char *str, size_t size, char *filename, int line_nr);
void memdbg_free(void *ptr, char *filename, int line_nr);
void memdbg_print_log(bool print_all);

#endif

#endif
