/*
 * queue for changes uploaded to LastPass
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
#include "upload-queue.h"
#include "session.h"
#include "http.h"
#include "util.h"
#include "config.h"
#include "kdf.h"
#include "process.h"
#include "password.h"
#include "endpoints.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>

static void upload_queue_write_entry(const char *entry, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *base_path = NULL;
	_cleanup_free_ char *name = NULL;
	struct stat sbuf;
	int ret;
	unsigned long serial;

	base_path = config_path("upload-queue");

	ret = stat(base_path, &sbuf);
	if ((ret == -1 && errno == ENOENT) || !S_ISDIR(sbuf.st_mode)) {
		unlink(base_path);
		if (mkdir(base_path, 0700) < 0)
			die_errno("mkdir(%s)", base_path);
	} else if (ret == -1)
		die_errno("stat(%s)", base_path);

	for (serial = 0; serial < ULONG_MAX; ++serial) {
		free(name);
		xasprintf(&name, "upload-queue/%lu%lu", time(NULL), serial);
		if (!config_exists(name))
			break;
	}
	if (serial == ULONG_MAX)
		die("No more upload queue entry slots available.");

	config_write_encrypted_string(name, entry, key);
}

static char *upload_queue_next_entry(unsigned const char key[KDF_HASH_LEN], char **name, char **lock)
{
	unsigned long long smallest = ULLONG_MAX, current;
	_cleanup_free_ char *smallest_name = NULL;
	_cleanup_free_ char *base_path = config_path("upload-queue");
	_cleanup_free_ char *pidstr = NULL;
	pid_t pid;
	char *result, *p;
	DIR *dir = opendir(base_path);
	struct dirent *entry;

	if (!dir)
		return NULL;
	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_REG)
			continue;
		for (p = entry->d_name; *p; ++p) {
			if (!isdigit(*p))
				break;
		}
		if (*p)
			continue;
		current = strtoull(entry->d_name, NULL, 10);
		if (!current)
			continue;
		if (current < smallest) {
			smallest = current;
			free(smallest_name);
			smallest_name = xstrdup(entry->d_name);
		}
	}
	closedir(dir);
	if (smallest == ULLONG_MAX)
		return NULL;

	xasprintf(name, "upload-queue/%s", smallest_name);
	xasprintf(lock, "%s.lock", *name);
	while (config_exists(*lock)) {
		free(pidstr);
		pidstr = config_read_encrypted_string(*lock, key);
		if (!pidstr) {
			config_unlink(*lock);
			break;
		}
		pid = strtoul(pidstr, NULL, 10);
		if (!pid) {
			config_unlink(*lock);
			break;
		}
		if (process_is_same_executable(pid))
			sleep(1);
		else {
			config_unlink(*lock);
			break;
		}
	}
	free(pidstr);
	pidstr = xultostr(getpid());
	config_write_encrypted_string(*lock, pidstr, key);
	result = config_read_encrypted_string(*name, key);
	if (!result) {
		config_unlink(*lock);
		return NULL;
	}
	return result;
}

static void upload_queue_cleanup(int signal)
{
	UNUSED(signal);
	config_unlink("uploader.pid");
	_exit(EXIT_SUCCESS);
}
static void upload_queue_upload_all(const struct session *session, unsigned const char key[KDF_HASH_LEN])
{
	char *entry, *next_entry, *result;
	int size;
	char **argv = NULL;
	char **argv_ptr;
	char *name, *lock, *p;
	bool do_break;
	bool should_fetch_new_blob_after = false;

	while ((entry = upload_queue_next_entry(key, &name, &lock))) {
		size = 0;
		for (p = entry; *p; ++p) {
			if (*p == '\n')
				++size;
		}
		if (p > entry && p[-1] != '\n')
			++size;
		if (size < 1) {
			config_unlink(name);
			config_unlink(lock);
			goto end;
		}
		argv_ptr = argv = xcalloc(size + 1, sizeof(char **));
		for (do_break = false, p = entry, next_entry = entry; ; ++p) {
			if (!*p)
				do_break = true;
			if (*p == '\n' || !*p) {
				*p = '\0';
				*(argv_ptr++) = pinentry_unescape(next_entry);
				next_entry = p + 1;
				if (do_break)
					break;
			}
		}
		argv[size] = NULL;
		for (int i = 0; i < 5; ++i) {
			sleep(i * 2);
			result = http_post_lastpass_v(argv[0], session->sessionid, NULL, &argv[1]);
			if (result && strlen(result))
				should_fetch_new_blob_after = true;
			free(result);
			if (result)
				break;
		}
		if (!result) {
			sleep(30);
			config_unlink(lock);
		} else {
			config_unlink(name);
			config_unlink(lock);
		}
		for (argv_ptr = argv; *argv_ptr; ++argv_ptr)
			free(*argv_ptr);
		free(argv);
end:
		free(name);
		free(lock);
		free(entry);
	}

	if (should_fetch_new_blob_after)
		blob_free(lastpass_get_blob(session, key));
}

static void upload_queue_run(const struct session *session, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *pid = NULL;
	upload_queue_kill();
	pid_t child = fork();
	if (child < 0)
		die_errno("fork(agent)");
	if (child == 0) {
		int null = open("/dev/null", 0);
		if (null >= 0) {
			dup2(null, 0);
			dup2(null, 1);
			dup2(null, 2);
			close(null);
		}
		setsid();
		IGNORE_RESULT(chdir("/"));
		process_set_name("lpass [upload queue]");
		signal(SIGHUP, upload_queue_cleanup);
		signal(SIGINT, upload_queue_cleanup);
		signal(SIGQUIT, upload_queue_cleanup);
		signal(SIGTERM, upload_queue_cleanup);
		signal(SIGALRM, upload_queue_cleanup);
		upload_queue_upload_all(session, key);
		upload_queue_cleanup(0);
		_exit(EXIT_SUCCESS);
	}
	pid = xultostr(child);
	config_write_string("uploader.pid", pid);
}

void upload_queue_kill(void)
{
	_cleanup_free_ char *pidstr = NULL;
	pid_t pid;

	pidstr = config_read_string("uploader.pid");
	if (!pidstr)
		return;
	pid = strtoul(pidstr, NULL, 10);
	if (!pid)
		return;
	kill(pid, SIGTERM);
}

bool upload_queue_is_running(void)
{
	_cleanup_free_ char *pidstr = NULL;
	pid_t pid;

	pidstr = config_read_string("uploader.pid");
	if (!pidstr)
		return false;
	pid = strtoul(pidstr, NULL, 10);
	if (!pid)
		return false;
	return process_is_same_executable(pid);
}

void upload_queue_enqueue(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const char *page, ...)
{
	_cleanup_free_ char *sum = xstrdup(page);
	char *next = NULL;
	char *escaped = NULL;
	va_list params;
	char *param;

	va_start(params, page);
	while ((param = va_arg(params, char *))) {
		escaped = pinentry_escape(param);
		xasprintf(&next, "%s\n%s", sum, escaped);
		free(escaped);
		free(sum);
		sum = next;
	}
	va_end(params);

	upload_queue_write_entry(sum, key);

	if (sync != BLOB_SYNC_NO)
		upload_queue_ensure_running(key, session);
}

void upload_queue_ensure_running(unsigned const char key[KDF_HASH_LEN], const struct session *session)
{
	if (!upload_queue_is_running())
		upload_queue_run(session, key);
}
