/*
 * terminal printing routines
 *
 * Copyright (C) 2014-2015 LastPass.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
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
