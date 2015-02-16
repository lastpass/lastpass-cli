/*
 * Copyright (c) 2014 LastPass.
 *
 * reallocarray is:
 *     Copyright (c) 2008 Otto Moerbeek <otto@drijf.net>.
 * strlcpy and strlcat are:
 *     Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>.
 * For reallocarray, strlcpy, and strlcat:
 *     Permission to use, copy, modify, and distribute this software for any
 *     purpose with or without fee is hereby granted, provided that the above
 *     copyright notice and this permission notice appear in all copies.
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *     WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *     MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *     ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *     WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *     ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *     OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "util.h"
#include "process.h"
#include "terminal.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/rand.h>

void warn(const char *err, ...)
{
	char message[4096];
	va_list params;

	va_start(params, err);
	vsnprintf(message, sizeof(message), err, params);
	va_end(params);

	terminal_fprintf(stderr, TERMINAL_FG_YELLOW TERMINAL_BOLD "Warning" TERMINAL_RESET ": %s\n", message);
}

void warn_errno(const char *err, ...)
{
	char message[4096], *error_message;
	va_list params;

	error_message = strerror(errno);

	va_start(params, err);
	vsnprintf(message, sizeof(message), err, params);
	va_end(params);

	terminal_fprintf(stderr, TERMINAL_FG_YELLOW TERMINAL_BOLD "WARNING" TERMINAL_RESET ": " TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", error_message, message);
}

_noreturn_ void die(const char *err, ...)
{
	char message[4096];
	va_list params;

	va_start(params, err);
	vsnprintf(message, sizeof(message), err, params);
	va_end(params);

	terminal_fprintf(stderr, TERMINAL_FG_RED TERMINAL_BOLD "Error" TERMINAL_RESET ": %s\n", message);
	exit(1);
}
_noreturn_ void die_errno(const char *err, ...)
{
	char message[4096], *error_message;
	va_list params;

	error_message = strerror(errno);

	va_start(params, err);
	vsnprintf(message, sizeof(message), err, params);
	va_end(params);

	terminal_fprintf(stderr, TERMINAL_FG_RED TERMINAL_BOLD "Error" TERMINAL_RESET ": " TERMINAL_FG_RED "%s" TERMINAL_RESET ": %s\n", error_message, message);
	exit(1);
}

void die_usage(const char *usage)
{
	terminal_fprintf(stderr, "Usage: %s %s\n", ARGV[0], usage);
	exit(1);
}

bool ask_yes_no(bool default_yes, const char *prompt, ...)
{
	va_list params;
	_cleanup_free_ char *response = NULL;
	size_t len = 0;

	for (;;) {
		va_start(params, prompt);
		terminal_fprintf(stderr, TERMINAL_FG_YELLOW);
		vfprintf(stderr, prompt, params);
		terminal_fprintf(stderr, TERMINAL_RESET);
		va_end(params);
		if (default_yes)
			terminal_fprintf(stderr, " [" TERMINAL_BOLD "Y" TERMINAL_RESET "/n] ");
		else
			terminal_fprintf(stderr, " [y/" TERMINAL_BOLD "N" TERMINAL_RESET "] ");
		if (getline(&response, &len, stdin) < 0)
			die("aborted response.");
		strlower(response);
		if (!strcmp("y\n", response) || !strcmp("yes\n", response))
			return true;
		else if (!strcmp("n\n", response) || !strcmp("no\n", response))
			return false;
		else if (!strcmp("\n", response))
			return default_yes;
		else {
			terminal_fprintf(stderr, TERMINAL_FG_RED TERMINAL_BOLD "Error" TERMINAL_RESET ": Response not understood.\n");
			free(response);
			response = NULL;
			len = 0;
		}
	}
}

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (likely(ret))
		return ret;
	die_errno("malloc(%zu)", size);
}
void *xcalloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (likely(ret))
		return ret;
	die_errno("calloc(%zu, %zu)", nmemb, size);
}
void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (likely(ret))
		return ret;
	die_errno("realloc(%p, %zu)", ptr, size);
}
void *reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(optr, size * nmemb);
}
void *xreallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *ret = reallocarray(ptr, nmemb, size);
	if (likely(ret))
		return ret;
	die_errno("reallocarray(%p, %zu, %zu)", ptr, nmemb, size);
}

void *xstrdup(const char *str)
{
	void *ret = strdup(str);
	if (likely(ret))
		return ret;
	die_errno("strdup(%p)", str);
}
void *xstrndup(const char *str, size_t maxlen)
{
	void *ret = strndup(str, maxlen);
	if (likely(ret))
		return ret;
	die_errno("strndup(%p, %zu)", str, maxlen);
}
int xasprintf(char **strp, const char *fmt, ...)
{
	va_list params;
	int ret;

	va_start(params, fmt);
	ret = xvasprintf(strp, fmt, params);
	va_end(params);

	return ret;
}
int xvasprintf(char **strp, const char *fmt, va_list ap)
{
	int ret;

	ret = vasprintf(strp, fmt, ap);
	if (ret == -1)
		die_errno("asprintf(%p, %s, ...)", (void *)strp, fmt);

	return ret;
}

#ifdef __GLIBC__
size_t strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return (s - src - 1);	/* count does not include NUL */
}
size_t strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return (dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return (dlen + (s - src));	/* count does not include NUL */
}
#else
char *strchrnul(const char *s, int c)
{
	char *p = strchr(s, c);
	if (!p)
		p = (char *)s + strlen(s);
	return p;
}
#endif

void strlower(char *str)
{
	for (; *str; ++str)
		*str = tolower(*str);
}
void strupper(char *str)
{
	for (; *str; ++str)
		*str = toupper(*str);
}
char *xstrlower(const char *str)
{
	char *copy = xstrdup(str);
	strlower(copy);
	return copy;
}
char *xstrupper(const char *str)
{
	char *copy = xstrdup(str);
	strupper(copy);
	return copy;
}
char *xultostr(unsigned long num)
{
	char *str;
	xasprintf(&str, "%ld", num);
	return str;
}

bool starts_with(const char *str, const char *start)
{
	for (; ; ++str, ++start) {
		if (!*start)
			return true;
		else if (*str != *start)
			return false;
	}
}
bool ends_with(const char *str, const char *end)
{
	int str_len = strlen(str);
	int end_len = strlen(end);
	if (str_len < end_len)
		return false;
	else
		return !strcmp(str + str_len - end_len, end);
}
char *trim(char *str)
{
	int start, i;

	for (start = 0; isspace(str[start]) && str[start]; ++start);

	for (i = 0; str[i + start]; ++i)
		str[i] = str[i + start];
	str[i] = '\0';

	for (--i; i >= 0 && isspace(str[i]); --i)
		str[i] = '\0';

	return str;
}

void xstrappend(char **str, const char *suffix)
{
	if (!*str) {
		*str = xstrdup(suffix);
		return;
	}
	size_t len = strlen(*str) + strlen(suffix) + 1;
	*str = xrealloc(*str, len);
	strlcat(*str, suffix, len);
}
void xstrappendf(char **str, const char *suffixfmt, ...)
{
	_cleanup_free_ char *fmt = NULL;
	va_list args;

	va_start(args, suffixfmt);
	xvasprintf(&fmt, suffixfmt, args);
	va_end(args);

	xstrappend(str, fmt);
}
void xstrprepend(char **str, const char *prefix)
{
	if (!*str) {
		*str = xstrdup(prefix);
		return;
	}
	size_t len = strlen(*str) + strlen(prefix) + 1;
	char *new = xmalloc(len);
	strlcpy(new, prefix, len);
	strlcat(new, *str, len);
	free(*str);
	*str = new;
}
void xstrprependf(char **str, const char *suffixfmt, ...)
{
	_cleanup_free_ char *fmt = NULL;
	va_list args;

	va_start(args, suffixfmt);
	xvasprintf(&fmt, suffixfmt, args);
	va_end(args);

	xstrprepend(str, fmt);
}

void secure_clear(void *ptr, size_t len)
{
	if (!ptr)
		return;

	memset(ptr, 0, len);
	/* prevent GCC / LLVM from optimizing out memset */
	asm volatile("" : : "r"(ptr) : "memory");
}

void secure_clear_str(char *str)
{
	if (!str)
		return;

	secure_clear(str, strlen(str));
}

void *secure_resize(void *ptr, size_t oldlen, size_t newlen)
{
	/* open-coded realloc, with a secure memset in the middle */
	void *newptr = xmalloc(newlen);
	if (ptr) {
		memcpy(newptr, ptr, min(oldlen, newlen));
		secure_clear(ptr, oldlen);
		free(ptr);
	}
	return newptr;
}

static char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
_unroll_ void bytes_to_hex(const char *bytes, char **hex, size_t len)
{
	if (!*hex)
		*hex = xmalloc(len * 2 + 1);
	for (size_t i = 0; i < len; ++i) {
		(*hex)[i * 2] = hex_digits[(bytes[i] >> 4) & 0xF];
		(*hex)[i * 2 + 1] = hex_digits[bytes[i] & 0xF];
	}
	(*hex)[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, char **bytes)
{
	size_t len = strlen(hex);
	if (len % 2 != 0) {
		if (!*bytes)
			*bytes = xcalloc(1, 1);
		**bytes = '\0';
		return -EINVAL;
	}
	if (!*bytes)
		*bytes = xmalloc(len / 2 + 1);
	for (size_t i = 0; i < len / 2; ++i) {
		if (sscanf(&hex[i * 2], "%2hhx", (unsigned char *)(*bytes + i)) != 1) {
			fprintf(stderr, "%s\n", hex);
			**bytes = '\0';
			return -EINVAL;
		}
	}
	(*bytes)[len / 2] = '\0';
	return 0;
}

/* [min, max) */
unsigned long range_rand(unsigned long min, unsigned long max)
{
	unsigned long base_random, range, remainder, bucket;

	if (!RAND_bytes((unsigned char *)&base_random, sizeof(base_random)))
		die("Could not generate random bytes.");
	if (ULONG_MAX == base_random)
		return range_rand(min, max);
	range = max - min;
	remainder = ULONG_MAX % range;
	bucket = ULONG_MAX / range;
	if (base_random < ULONG_MAX - remainder)
		return min + base_random / bucket;
	return range_rand(min, max);
}
