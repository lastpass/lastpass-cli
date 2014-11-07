/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "terminal.h"
#include "util.h"
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

static enum color_mode color_mode = COLOR_MODE_AUTO;

static void filter_ansi(FILE *file, const char *fmt, va_list args)
{
	_cleanup_free_ char *str = NULL;
	size_t len, i, j;

	if (color_mode == COLOR_MODE_ALWAYS ||
	    (color_mode == COLOR_MODE_AUTO && isatty(fileno(file)))) {
		vfprintf(file, fmt, args);
		return;
	}

	len = xvasprintf(&str, fmt, args);

	for (i = 0; i < len - 2; ++i) {
		if (str[i] == '\x1b' && str[i + 1] == '[') {
			str[i] = str[i + 1] = '\0';
			for (j = i + 2; j < len; ++j) {
				if (isalpha(str[j]))
					break;
				str[j] = '\0';
			}
			str[j] = '\0';
		}
	}
	for (i = 0; i < len; i = j) {
		fputs(&str[i], file);
		for (j = i + strlen(&str[i]); j < len; ++j) {
			if (str[j] != '\0')
				break;
		}
	}
}

void terminal_set_color_mode(enum color_mode mode)
{
	color_mode = mode;
}

void terminal_printf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	filter_ansi(stdout, fmt, args);
	va_end(args);
}

void terminal_fprintf(FILE *file, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	filter_ansi(file, fmt, args);
	va_end(args);
}
