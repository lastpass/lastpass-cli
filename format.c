/*
 * printf-like formatting routines
 *
 * Copyright (C) 2014-2018 LastPass.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include "cmd.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "kdf.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

char *get_display_fullname(struct account *account)
{
	char *fullname = NULL;

	if (account->share || strcmp(account->group, ""))
		fullname = xstrdup(account->fullname);
	else
		xasprintf(&fullname, "(none)/%s", account->fullname);

	return fullname;
}

char *format_timestamp(char *timestamp, bool utc)
{
	char temp[60];
	struct tm *ts_tm;

	if (!timestamp)
		return xstrdup("");

	time_t ts_time_t = (time_t) strtoul(timestamp, NULL, 10);

	if (ts_time_t == 0)
		return xstrdup("");

	if (utc)
		ts_tm = gmtime(&ts_time_t);
	else
		ts_tm = localtime(&ts_time_t);

	strftime(temp, sizeof(temp), "%Y-%m-%d %H:%M", ts_tm);

	return xstrdup(temp);
}

static
void append_str(struct buffer *buf, char *str, bool add_slash)
{
	if (!str || !strlen(str))
		return;

	buffer_append_str(buf, str);
	if (add_slash)
		buffer_append_char(buf, '/');
}

static
void format_account_item(struct buffer *buf, char fmt,
			 struct account *account, bool add_slash)
{
	_cleanup_free_ char *name = NULL;
	_cleanup_free_ char *ts = NULL;

	switch (fmt) {
	case 'i':
		/* id */
		append_str(buf, account->id, add_slash);
		break;
	case 'n':
		/* shortname */
		append_str(buf, account->name, add_slash);
		break;
	case 'N':
		/* fullname */
		name = get_display_fullname(account);
		append_str(buf, name, add_slash);
		break;
	case 'u':
		/* username */
		append_str(buf, account->username, add_slash);
		break;
	case 'p':
		/* password */
		append_str(buf, account->password, add_slash);
		break;
	case 'm':
		/* mtime */
		ts = format_timestamp(account->last_modified_gmt, true);
		append_str(buf, ts, add_slash);
		break;
	case 'U':
		/* last touch time */
		ts = format_timestamp(account->last_touch, false);
		append_str(buf, ts, add_slash);
		break;
	case 's':
		/* sharename */
		if (account->share)
			append_str(buf, account->share->name, add_slash);
		break;
	case 'g':
		/* group name */
		append_str(buf, account->group, add_slash);
		break;
	case 'l':
		/* URL */
		append_str(buf, account->url, add_slash);
		break;
	default:
		break;
	}
}

void format_field_item(struct buffer *buf, char fmt,
		       char *field_name, char *field_value,
		       bool add_slash)
{
	if (fmt == 'n' && field_name) {
		append_str(buf, field_name, add_slash);
	} else if (fmt == 'v' && field_value) {
		append_str(buf, field_value, add_slash);
	}
}

void format_field(struct buffer *buf, const char *format_str,
		  struct account *account,
		  char *field_name, char *field_value)
{
	const char *p = format_str;
	bool in_format = false;
	bool add_slash = false;

	while (*p) {
		char ch = *p++;

		if (!in_format) {
			if (ch == '%')
				in_format = true;
			else
				buffer_append_char(buf, ch);
			continue;
		}

		/* expand format specifiers */
		switch (ch)
		{
		case '%':
			/* %% escape */
			buffer_append_char(buf, ch);
			break;
		case '/':
			/* append trailing slash, if nonempty */
			add_slash = true;
			continue;
		case 'f':
			/* field name/value */
			if (!*p) {
				buffer_append_char(buf, '%');
				buffer_append_char(buf, ch);
				break;
			}
			ch = *p++;
			format_field_item(buf, ch, field_name, field_value, add_slash);
			break;
		case 'a':
			/* account item */
			if (!*p) {
				buffer_append_char(buf, '%');
				buffer_append_char(buf, ch);
				break;
			}
			ch = *p++;
			format_account_item(buf, ch, account, add_slash);
			break;
		default:
			buffer_append_char(buf, '%');
			buffer_append_char(buf, ch);
		}
		add_slash = false;
		in_format = false;
	}
}

void format_account(struct buffer *buf, const char *fmt_str,
		    struct account *account)
{
	format_field(buf, fmt_str, account, NULL, NULL);
}
