/*
 * logging functions
 *
 * Copyright (C) 2016 LastPass.
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
 * version of the file(s), but you are not obligated to do so.	If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
 */
#include "util.h"
#include "log.h"
#include "config.h"
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>

#define TIME_FMT "%lld.%06lld"
#define TIME_ARGS(tv) ((long long)(tv)->tv_sec), ((long long)(tv)->tv_usec)

static int initialized	= 0;
static int level = LOG_LEVEL_NONE;
static int log_to_stderr = 0;

int lpass_log_level()
{
	char *log_level_str;

	if (initialized)
		return (enum log_level) level;

	if (getenv("LPASS_LOG_STDERR"))
		lpass_log_set_log_to_stderr();

	log_level_str = getenv("LPASS_LOG_LEVEL");
	if (!log_level_str) {
		initialized = true;
		level = LOG_LEVEL_NONE;
		return (enum log_level) level;
	}

	level = strtoul(log_level_str, NULL, 10);
	initialized = 1;
	return (enum log_level) level;
}

void lpass_log_set_log_to_stderr() {
	log_to_stderr = 1;
}

const char* lpass_log_level_string() {
	if (lpass_log_is_verbose())	return "VERBOSE";
	if (lpass_log_is_debug())		return "DEBUG";
	if (lpass_log_is_info())		return "INFO";
	if (lpass_log_is_warning())	return "WARNING";
	if (lpass_log_is_error())		return "ERROR";
	return "NONE";
}

int lpass_log_is_none() {
	return lpass_log_level() >= LOG_LEVEL_NONE;
}

int lpass_log_is_error() {
	return lpass_log_level() >= LOG_LEVEL_ERROR;
}

int lpass_log_is_warning() {
	return lpass_log_level() >= LOG_LEVEL_WARNING;
}

int lpass_log_is_info() {
	return lpass_log_level() >= LOG_LEVEL_INFO;
}

int lpass_log_is_debug() {
	return lpass_log_level() >= LOG_LEVEL_DEBUG;
}

int lpass_log_is_verbose() {
	return lpass_log_level() >= LOG_LEVEL_VERBOSE;
}

const char* lpass_short_fname(const char* fname)
{
	const char* pos = strrchr(fname, '/');
	if (!pos) {
		return fname;
	}

	return pos+1;
}

void lpass_log(enum log_level level, char *fmt, ...)
{
	struct timeval tv;
	struct timezone tz;
	va_list ap;
	_cleanup_fclose_ FILE *fp = NULL;

	int req_level = lpass_log_level();

	if (req_level < level)
		return;

	fp = lpass_log_open();
	if (!fp)
		return;

	gettimeofday(&tv, &tz);
	fprintf(fp, "<%-7s> [" TIME_FMT "] ", lpass_log_level_string(level), TIME_ARGS(&tv));
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fflush(fp);


	if (log_to_stderr) {
		fprintf(stderr, "<%-7s> [" TIME_FMT "] ", lpass_log_level_string(level), TIME_ARGS(&tv));
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

FILE *lpass_log_open()
{
	_cleanup_free_ char *upload_log_path = NULL;

	if (lpass_log_level() < 0)
		return NULL;

	upload_log_path = config_path("lpass.log");
	return fopen(upload_log_path, "a");
}

const char* lpass_log_bool_to_string(int b)
{
	return b ? "true" : "false";
}
