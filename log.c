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
 * version of the file(s), but you are not obligated to do so.  If you
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
#include <sys/time.h>

#define TIME_FMT "%lld.%06lld"
#define TIME_ARGS(tv) ((long long)(tv)->tv_sec), ((long long)(tv)->tv_usec)

int lpass_log_level()
{
	char *log_level_str;
	int level;

	log_level_str = getenv("LPASS_LOG_LEVEL");
	if (!log_level_str)
		return LOG_NONE;

	level = strtoul(log_level_str, NULL, 10);
	return (enum log_level) level;
}

void lpass_log(enum log_level level, char *fmt, ...)
{
	struct timeval tv;
	struct timezone tz;
	va_list ap;
	_cleanup_fclose_ FILE *fp;

	int req_level = lpass_log_level();

	if (req_level < level)
		return;

	fp = lpass_log_open();
	if (!fp)
		return;

	gettimeofday(&tv, &tz);
	fprintf(fp, "<%d> [" TIME_FMT "] ", level, TIME_ARGS(&tv));
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fflush(fp);
}

FILE *lpass_log_open()
{
	_cleanup_free_ char *upload_log_path = NULL;

	if (lpass_log_level() < 0)
		return NULL;

	upload_log_path = config_path("lpass.log");
	return fopen(upload_log_path, "a");
}
