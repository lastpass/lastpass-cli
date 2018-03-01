/*
 * queue for changes uploaded to LastPass
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
#include "upload-queue.h"
#include "session.h"
#include "http.h"
#include "util.h"
#include "config.h"
#include "kdf.h"
#include "log.h"
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

/* keep around failed updates for a couple of weeks */
#define FAIL_MAX_AGE	86400 * 14

static void make_upload_dir(const char *path)
{
	_cleanup_free_ char *base_path = NULL;
	struct stat sbuf;
	int ret;

	base_path = config_path(path);

	ret = stat(base_path, &sbuf);
	if ((ret == -1 && errno == ENOENT) || !S_ISDIR(sbuf.st_mode)) {
		unlink(base_path);
		if (mkdir(base_path, 0700) < 0)
			die_errno("mkdir(%s)", base_path);
	} else if (ret == -1)
		die_errno("stat(%s)", base_path);

}

static void upload_queue_write_entry(const char *entry, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *name = NULL;
	unsigned long serial;

	make_upload_dir("upload-queue");

	for (serial = 0; serial < ULONG_MAX; ++serial) {
		free(name);
		xasprintf(&name, "upload-queue/%lu%04lu", time(NULL), serial);
		if (!config_exists(name))
			break;
	}
	if (serial == ULONG_MAX)
		die("No more upload queue entry slots available.");

	config_write_encrypted_string(name, entry, key);
}

static void upload_queue_cleanup_failures()
{
	_cleanup_free_ char *base_path = config_path("upload-fail");
	DIR *dir = opendir(base_path);
	struct dirent *entry;
	char *p;
	struct stat sbuf;
	int ret;

	if (!dir)
		return;

	while ((entry = readdir(dir))) {
		_cleanup_free_ char *fn = NULL;

		if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN)
			continue;

		for (p = entry->d_name; *p; ++p) {
			if (!isdigit(*p))
				break;
		}
		if (*p)
			continue;

		xasprintf(&fn, "%s/%s", base_path, entry->d_name);
		ret = stat(fn, &sbuf);
		if (ret)
			continue;

		if ((time(NULL) - sbuf.st_mtime) > FAIL_MAX_AGE) {
			unlink(fn);
		}
	}
	closedir(dir);
}

static void upload_queue_drop(const char *name)
{
	_cleanup_free_ char *newname = NULL;
	_cleanup_free_ char *old_full = NULL;
	_cleanup_free_ char *new_full = NULL;
	char *basename;
	int ret;

	lpass_log(LOG_DEBUG, "UQ: dropping %s\n", name);

	make_upload_dir("upload-fail");

	basename = strrchr(name, '/');
	if (!basename) {
		unlink(name);
		return;
	}
	basename += 1;
	xasprintf(&newname, "upload-fail/%s", basename);

	old_full = config_path(name);
	new_full = config_path(newname);
	ret = rename(old_full, new_full);

	lpass_log(LOG_DEBUG, "UQ: rename returned %d (errno=%d)\n", ret, errno);

	upload_queue_cleanup_failures();
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
		if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN)
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
		/* could not decrypt: drop this file */
		lpass_log(LOG_DEBUG, "UQ: unable to decrypt job %s\n", *name);
		upload_queue_drop(*name);
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
	int curl_ret;
	long http_code;
	bool http_failed_all;
	int backoff;
	int backoff_scale = 8;

	while ((entry = upload_queue_next_entry(key, &name, &lock))) {

		lpass_log(LOG_DEBUG, "UQ: processing job %s\n", name);

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

		http_failed_all = true;
		backoff = 1;
		for (int i = 0; i < 5; ++i) {
			if (i) {
				lpass_log(LOG_DEBUG, "UQ: attempt %d, sleeping %d seconds\n", i+1, backoff);
				sleep(backoff);
				backoff *= backoff_scale;
			}

			lpass_log(LOG_DEBUG, "UQ: posting to %s\n", argv[0]);

			result = http_post_lastpass_v_noexit(session->server, argv[0],
				session, NULL, &argv[1],
				&curl_ret, &http_code);

			http_failed_all &=
				(curl_ret == HTTP_ERROR_CODE ||
				 curl_ret == HTTP_ERROR_CONNECT);

			lpass_log(LOG_DEBUG, "UQ: result %d (http_code=%ld)\n", curl_ret, http_code);

			if (http_code == 500) {
				/* not a rate-limit error; try again with less backoff */
				backoff_scale = 2;
			} else {
				backoff_scale = 8;
			}

			if (result && strlen(result))
				should_fetch_new_blob_after = true;
			free(result);
			if (result)
				break;
		}
		if (!result) {
			lpass_log(LOG_DEBUG, "UQ: failed, http_failed_all: %d\n", http_failed_all);

			/* server failed response 5 times, remove it */
			if (http_failed_all)
				upload_queue_drop(name);

			config_unlink(lock);
		} else {
			lpass_log(LOG_DEBUG, "UQ: succeeded\n");
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
		int upload_log = null;

		if (null >= 0) {
			dup2(null, 0);
			dup2(null, 1);
			dup2(null, 2);
			close(null);
			close(upload_log);
		}
		setsid();
		IGNORE_RESULT(chdir("/"));
		process_set_name("lpass [upload queue]");
		signal(SIGHUP, upload_queue_cleanup);
		signal(SIGINT, upload_queue_cleanup);
		signal(SIGQUIT, upload_queue_cleanup);
		signal(SIGTERM, upload_queue_cleanup);
		signal(SIGALRM, upload_queue_cleanup);
		setvbuf(stdout, NULL, _IOLBF, 0);

		if (http_init()) {
			lpass_log(LOG_ERROR, "UQ: unable to restart curl\n");
			_exit(EXIT_FAILURE);
		}

		lpass_log(LOG_DEBUG, "UQ: starting queue run\n");
		upload_queue_upload_all(session, key);
		lpass_log(LOG_DEBUG, "UQ: queue run complete\n");
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

void upload_queue_enqueue(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const char *page, struct http_param_set *params)
{
	_cleanup_free_ char *sum = xstrdup(page);
	char *next = NULL;
	char *escaped = NULL;
	char *param;
	char **argv = params->argv;

	while ((param = *argv++)) {
		escaped = pinentry_escape(param);
		xasprintf(&next, "%s\n%s", sum, escaped);
		free(escaped);
		free(sum);
		sum = next;
	}

	upload_queue_write_entry(sum, key);

	if (sync != BLOB_SYNC_NO)
		upload_queue_ensure_running(key, session);
}

void upload_queue_ensure_running(unsigned const char key[KDF_HASH_LEN], const struct session *session)
{
	if (!upload_queue_is_running())
		upload_queue_run(session, key);
}
