#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdarg.h>

#ifndef min
#define min(x,y) (((x) < (y)) ? (x) : (y))
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define _noreturn_ __attribute__((noreturn))
#if !defined(__clang__)
#define _unroll_ __attribute__((optimize("unroll-loops")))
#else
#define _unroll_
#endif
#define _printf_(x, y) __attribute__((format(printf, x, y)))
#define _cleanup_(x) __attribute__((cleanup(x)))

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
	static inline void func##p(type *p) {                   \
		if (*p)                                         \
			func(*p);                               \
	}
DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, fclose)
DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, pclose)
DEFINE_TRIVIAL_CLEANUP_FUNC(DIR*, closedir)
#undef DEFINE_TRIVIAL_CLEANUP_FUNC
static inline void umaskp(mode_t *u) {
	umask(*u);
}
static inline void freep(void *p) {
	free(*(void**) p);
}
#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_umask_ _cleanup_(umaskp)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_pclose_ _cleanup_(pclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)

#define new0(t, l) ((t*) xcalloc((l), sizeof(t)))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define UNUSED(x) (void)(x)
#define IGNORE_RESULT(x) do { int z = x; (void)sizeof(z); } while (0)

#define MUL_NO_OVERFLOW (1UL << (sizeof(size_t) * 4))

void warn(const char *err, ...) _printf_(1, 2);
void warn_errno(const char *err, ...) _printf_(1, 2);
_noreturn_ void die(const char *err, ...) _printf_(1, 2);
_noreturn_ void die_errno(const char *err, ...) _printf_(1, 2);
_noreturn_ void die_usage(const char *usage);
bool ask_yes_no(bool default_yes, const char *prompt, ...);

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);
void *reallocarray(void *ptr, size_t nmemb, size_t size);
void *xreallocarray(void *ptr, size_t nmemb, size_t size);

void *xstrdup(const char *str);
void *xstrndup(const char *str, size_t maxlen);
int xasprintf(char **strp, const char *fmt, ...) _printf_(2, 3);
int xvasprintf(char **strp, const char *fmt, va_list ap);

#ifdef __GLIBC__
size_t strlcpy(char *dst, const char *src, size_t dstsize);
size_t strlcat(char *dst, const char *src, size_t dstsize);
#else
char *strchrnul(const char *s, int c);
#endif

void strlower(char *str);
void strupper(char *str);
char *xstrlower(const char *str);
char *xstrupper(const char *str);

char *xultostr(unsigned long num);

void xstrappend(char **str, const char *suffix);
void xstrappendf(char **str, const char *suffixfmt, ...) _printf_(2, 3);
void xstrprepend(char **str, const char *suffix);
void xstrprependf(char **str, const char *suffixfmt, ...) _printf_(2, 3);

bool starts_with(const char *str, const char *start);
bool ends_with(const char *str, const char *end);

char *trim(char *str);

void bytes_to_hex(const char *bytes, char **hex, size_t len);
int hex_to_bytes(const char *hex, char **bytes);

void secure_clear(void *ptr, size_t len);
void secure_clear_str(char *str);
void *secure_resize(void *ptr, size_t oldlen, size_t newlen);

/* [min, max) */
unsigned long range_rand(unsigned long min, unsigned long max);

#endif
