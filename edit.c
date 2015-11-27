/*
 * common routines for editing / adding accounts
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
#include "endpoints.h"
#include "blob.h"
#include "agent.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "util.h"

#if defined(__linux__) || defined(__CYGWIN__)
static char *shared_memory_dir(void)
{
	return xstrdup("/dev/shm");
}
#elif defined(__APPLE__) && defined(__MACH__)
static const char *shared_memory_dir_mount =
"dir=\"$(mktemp -d \"${TMPDIR:-/tmp}/lpass.XXXXXXXXXXXXX\")\"\n"
"dev=\"$(hdid -drivekey system-image=yes -nomount 'ram://32768' | cut -d ' ' -f 1)\"\n"
"[[ -z $dev ]] && exit 1\n"
"newfs_hfs -M 700 \"$dev\" >/dev/null 2>&1 || exit 1\n"
"mount -t hfs -o noatime -o nobrowse \"$dev\" \"$dir\" || exit 1\n"
"echo \"$dev\"\necho \"$dir\"\n";
static const char *shared_memory_dir_unmount =
"umount \"$SECURE_TMPDIR\"\n"
"diskutil quiet eject \"$RAMDISK_DEV\"\n"
"rm -rf \"$SECURE_TMPDIR\"\n";
static void shared_memory_dir_eject(void)
{
	system(shared_memory_dir_unmount);
}
static char *shared_memory_dir(void)
{
	char *stored = getenv("SECURE_TMPDIR");
	if (stored)
		return xstrdup(stored);

	_cleanup_free_ char *dev = NULL;
	char *dir = NULL;
	size_t len;
	FILE *script = popen(shared_memory_dir_mount, "r");

	if (!script)
		return NULL;

	len = 0;
	if (getline(&dev, &len, script) <= 0) {
		pclose(script);
		return NULL;
	}
	trim(dev);

	len = 0;
	if (getline(&dir, &len, script) <= 0) {
		pclose(script);
		return NULL;
	}
	trim(dir);

	setenv("SECURE_TMPDIR", dir, true);
	setenv("RAMDISK_DEV", dev, true);
	atexit(shared_memory_dir_eject);

	return dir;
}
#else
static char *shared_memory_dir(void)
{
	char *tmpdir = getenv("SECURE_TMPDIR");
	if (!tmpdir) {
		if (!(tmpdir = getenv("TMPDIR")))
			tmpdir = "/tmp";

		fprintf(stderr,
			"Warning: Using %s as secure temporary directory.\n"
			"Recommend using tmpfs and encrypted swap.\n"
			"Set SECURE_TMPDIR environment variable to override.\n",
			tmpdir);
		sleep(5);
	}
	return xstrdup(tmpdir);
}
#endif
_noreturn_ static inline void die_unlink_errno(const char *str, const char *file, const char *dir)
{
	int saved = errno;
	if (file)
		unlink(file);
	if (dir)
		rmdir(dir);
	errno = saved;
	die_errno("%s", str);
}

int edit_account(struct session *session,
		 struct blob *blob,
		 enum blobsync sync,
		 struct account *editable,
		 enum edit_choice choice,
		 const char *field,
		 bool non_interactive,
		 unsigned char key[KDF_HASH_LEN])
{
	size_t len, read;
	struct account *notes_expansion, *notes_collapsed = NULL;
	struct field *editable_field = NULL;
	_cleanup_free_ char *tmppath = NULL;
	_cleanup_free_ char *tmpdir = NULL;
	_cleanup_free_ char *editcmd = NULL;
	int tmpfd;
	FILE *tmpfile;
	char *value;

	notes_expansion = notes_expand(editable);
	if (notes_expansion) {
		notes_collapsed = editable;
		editable = notes_expansion;
	} else if (choice == EDIT_FIELD)
		die("Editing fields of entries that are not secure notes is currently not supported.");

	if (choice == EDIT_USERNAME)
		value = editable->username;
	else if (choice == EDIT_PASSWORD)
		value = editable->password;
	else if (choice == EDIT_URL)
		value = editable->url;
	else if (choice == EDIT_NAME)
		value = editable->fullname;
	else if (choice == EDIT_FIELD) {
		list_for_each_entry(editable_field, &editable->field_head, list) {
			if (!strcmp(editable_field->name, field))
				break;
		}
		if (!editable_field) {
			editable_field = new0(struct field, 1);
			editable_field->type = xstrdup("text");
			editable_field->name = xstrdup(field);
			field_set_value(editable, editable_field, xstrdup(""), key);

			list_add(&editable_field->list, &editable->field_head);
		}
		value = editable_field->value;
	} else if (choice == EDIT_NOTES)
		value = editable->note;

	if (!non_interactive) {
		if (editable->pwprotect) {
			unsigned char pwprotect_key[KDF_HASH_LEN];
			if (!agent_load_key(pwprotect_key))
				die("Could not authenticate for protected entry.");
			if (memcmp(pwprotect_key, key, KDF_HASH_LEN))
				die("Current key is not on-disk key.");
		}

		if (strcmp(editable->id, "0"))
			lastpass_log_access(sync, session, key, editable);

		tmpdir = shared_memory_dir();
		xstrappend(&tmpdir, "/lpass.XXXXXX");
		if (!mkdtemp(tmpdir))
			die_errno("mkdtemp");
		xasprintf(&tmppath, "%s/lpass.XXXXXX", tmpdir);
		tmpfd = mkstemp(tmppath);
		if (tmpfd < 0)
			die_unlink_errno("mkstemp", tmppath, tmpdir);
		tmpfile = fdopen(tmpfd, "w");
		if (!tmpfile)
			die_unlink_errno("fdopen", tmppath, tmpdir);
		if (fprintf(tmpfile, "%s\n", value) < 0)
			die_unlink_errno("fprintf", tmppath, tmpdir);
		fclose(tmpfile);

		xasprintf(&editcmd, "${EDITOR:-vi} '%s'", tmppath);
		if (system(editcmd) < 0)
			die_unlink_errno("system($EDITOR)", tmppath, tmpdir);

		tmpfile = fopen(tmppath, "r");
	} else
		tmpfile = stdin;
	if (!tmpfile)
		die_unlink_errno("fopen", tmppath, tmpdir);

	if (choice == EDIT_NOTES) {
		for (len = 0, value = xmalloc(8192 + 1); ; value = xrealloc(value, len + 8192 + 1)) {
			read = fread(value + len, 1, 8192, tmpfile);
			len += read;
			if (read != 8192) {
				if (ferror(tmpfile))
					die_unlink_errno("fread(tmpfile)", tmppath, tmpdir);
				break;
			}
		}
		value[len] = '\0';
	} else {
		value = NULL;
		len = 0;
		if (getline(&value, &len, tmpfile) < 0)
			die_unlink_errno("getline", tmppath, tmpdir);
	}
	fclose(tmpfile);
	len = strlen(value);
	if (len && value[len - 1] == '\n')
		value[len - 1] = '\0';
	if (tmppath) {
		unlink(tmppath);
		rmdir(tmpdir);
	}

	if (choice == EDIT_USERNAME)
		account_set_username(editable, value, key);
	else if (choice == EDIT_PASSWORD)
		account_set_password(editable, value, key);
	else if (choice == EDIT_URL) {
		free(editable->url);
		editable->url = value;
	} else if (choice == EDIT_NAME)
		account_set_fullname(editable, value, key);
	else if (choice == EDIT_NOTES)
		account_set_note(editable, value, key);
	else if (choice == EDIT_FIELD) {
		if (!strlen(value)) {
			list_del(&editable_field->list);
			field_free(editable_field);
		} else
			field_set_value(editable, editable_field, value, key);
	}

	if (notes_expansion && notes_collapsed) {
		editable = notes_collapsed;
		notes_collapsed = notes_collapse(notes_expansion);
		account_free(notes_expansion);
		account_set_note(editable, xstrdup(notes_collapsed->note), key);
		if (choice == EDIT_NAME)
			account_set_fullname(editable, xstrdup(notes_collapsed->fullname), key);
		account_free(notes_collapsed);
	}

	lastpass_update_account(sync, key, session, editable, blob);
	blob_save(blob, key);

	session_free(session);
	blob_free(blob);
	return 0;
}
