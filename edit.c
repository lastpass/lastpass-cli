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

static void assign_account_value(struct account *account,
				 const char *label,
				 char *value,
				 unsigned char key[KDF_HASH_LEN])
{
	struct field *editable_field = NULL;

#define assign_if(title, field) do { \
	if (!strcmp(label, title)) { \
		account_set_##field(account, value, key); \
		return; \
	} \
	} while (0)

	value = xstrdup(trim(value));

	assign_if("Name", fullname);
	assign_if("URL", url);
	assign_if("Username", username);
	assign_if("Password", password);

	/* if we got here maybe it's a secure note field */
	list_for_each_entry(editable_field, &account->field_head, list) {
		if (!strcmp(label, editable_field->name)) {
			field_set_value(account, editable_field, value, key);
			break;
		}
	}

#undef assign_if
}

static
int read_file_buf(FILE *fp, char **value_out, size_t *len_out)
{
	size_t len;
	size_t read;
	char *value;

	*len_out = 0;
	*value_out = NULL;

	for (len = 0, value = xmalloc(8192 + 1); ; value = xrealloc(value, len + 8192 + 1)) {
		read = fread(value + len, 1, 8192, fp);
		len += read;
		if (read != 8192) {
			if (ferror(fp))
				return -EIO;
			break;
		}
	}
	value[len] = '\0';
	*value_out = value;
	*len_out = len;
	return 0;
}

/*
 * Read a file representing all of the data in an account.
 * We generate this file when editing an account, and parse it back
 * after a user has edited it.  Each line, with the exception of the
 * final "notes" label, is parsed from the end of the label to the
 * first newline.  In the case of notes, the rest of the file is considered
 * part of the note.
 *
 * Name: text0
 * URL: text1
 * [...]
 * Notes:
 * notes text here
 *
 */
static void parse_account_file(FILE *input, struct account *account,
			       unsigned char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *line = NULL;
	ssize_t read;
	size_t len = 0;
	char *label, *delim, *value;
	bool parsing_notes = false;
	int ret;

	/* parse label: [value] */
	while ((read = getline(&line, &len, input)) != -1) {
		delim = strchr(line, ':');
		if (!delim)
			continue;
		*delim = 0;
		value = delim + 1;
		label = line;

		if (!strcmp(label, "Notes")) {
			parsing_notes = true;
			break;
		}
		assign_account_value(account, label, value, key);
	}

	if (!parsing_notes)
		return;

	/* everything else goes into notes section */
	value = NULL;
	len = 0;
	ret = read_file_buf(input, &value, &len);
	if (ret)
		return;

	account_set_note(account, value, key);
}

static int write_account_file(FILE *fp, struct account *account)
{
	struct field *editable_field = NULL;

#define write_field(title, field) do { \
	if (fprintf(fp, "%s: %s\n", title, field) < 0) \
		return -errno; \
	} while (0)

	write_field("Name", account->fullname);
	write_field("URL", account->url);
	write_field("Username", account->username);
	write_field("Password", account->password);

	list_for_each_entry(editable_field, &account->field_head, list) {
		write_field(editable_field->name, editable_field->value);
	}

	if (fprintf(fp, "Notes:    # Add notes below this line.\n%s", account->note) < 0)
		return -errno;

	return 0;
#undef write_field
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
	size_t len;
	struct account *notes_expansion, *notes_collapsed = NULL;
	struct field *editable_field = NULL;
	_cleanup_free_ char *tmppath = NULL;
	_cleanup_free_ char *tmpdir = NULL;
	_cleanup_free_ char *editcmd = NULL;
	int tmpfd;
	FILE *tmpfile;
	char *value;
	int ret;

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

		if (choice == EDIT_ANY) {
			if (write_account_file(tmpfile, editable))
				die_unlink_errno("fprintf", tmppath, tmpdir);
		} else {
			if (fprintf(tmpfile, "%s\n", value) < 0)
				die_unlink_errno("fprintf", tmppath, tmpdir);
		}
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
		ret = read_file_buf(tmpfile, &value, &len);
		if (ret)
			die_unlink_errno("fread(tmpfile)", tmppath, tmpdir);
	} else if (choice == EDIT_ANY) {
		parse_account_file(tmpfile, editable, key);
		value = NULL;
	} else {
		value = NULL;
		len = 0;
		if (getline(&value, &len, tmpfile) < 0)
			die_unlink_errno("getline", tmppath, tmpdir);
	}
	fclose(tmpfile);

	if (value) {
		len = strlen(value);
		if (len && value[len - 1] == '\n')
			value[len - 1] = '\0';
	}
	if (tmppath) {
		unlink(tmppath);
		rmdir(tmpdir);
	}

	if (choice == EDIT_USERNAME)
		account_set_username(editable, value, key);
	else if (choice == EDIT_PASSWORD)
		account_set_password(editable, value, key);
	else if (choice == EDIT_URL)
		account_set_url(editable, value, key);
	else if (choice == EDIT_NAME)
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

int edit_new_account(struct session *session,
		     struct blob *blob,
		     enum blobsync sync,
		     const char *name,
		     enum edit_choice choice,
		     const char *field,
		     bool non_interactive,
		     unsigned char key[KDF_HASH_LEN])
{
	struct account *account;

	account = new_account();
	account_assign_share(blob, account, name);

	account->id = xstrdup("0");
	account_set_password(account, xstrdup(""), key);
	account_set_fullname(account, xstrdup(name), key);
	account_set_username(account, xstrdup(""), key);
	account_set_note(account, xstrdup(""), key);
	if (choice == EDIT_NOTES) {
		account->url = xstrdup("http://sn");
	} else {
		account->url = xstrdup("");
	}
	list_add(&account->list, &blob->account_head);

	return edit_account(session, blob, sync, account, choice, field,
			    non_interactive, key);
}
