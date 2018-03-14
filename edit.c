/*
 * common routines for editing / adding accounts
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
#include "endpoints.h"
#include "blob.h"
#include "agent.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "util.h"

#define MAX_NOTE_LEN (unsigned long) 45000

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
				 int lineno,
				 unsigned char key[KDF_HASH_LEN])
{
	struct field *editable_field = NULL;

#define assign_if(title, field) do { \
	if (!strcmp(label, title)) { \
		account_set_##field(account, xstrdup(trim(value)), key); \
		return; \
	} \
	} while (0)

	/*
	 * "Name" may be used in note templates; only assign fullname
	 * in the first line.
	 */
	if (lineno == 1) {
		assign_if("Name", fullname);
	}
	assign_if("URL", url);
	assign_if("Username", username);
	assign_if("Password", password);
	assign_if("Application", appname);
	assign_if("Notes", note);

	if (!strcmp(label, "Reprompt")) {
		account->pwprotect = !strcmp(trim(value), "Yes");
		return;
	}

	/* if we got here maybe it's a secure note field */
	list_for_each_entry(editable_field, &account->field_head, list) {
		if (!strcmp(label, editable_field->name)) {
			field_set_value(account, editable_field,
					xstrdup(trim(value)), key);
			return;
		}
	}

	/* Some other name: value pair -- treat like a new field */
	editable_field = new0(struct field, 1);
	editable_field->name = xstrdup(label);
	editable_field->type = xstrdup("password");
	field_set_value(account, editable_field, xstrdup(trim(value)), key);
	list_add_tail(&editable_field->list, &account->field_head);

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

enum note_type get_note_type(struct account *account)
{
	struct field *editable_field;

	list_for_each_entry(editable_field, &account->field_head, list) {
		if (!strcmp(editable_field->name, "NoteType")) {
			return notes_get_type_by_name(editable_field->value);
		}
	}
	return NOTE_TYPE_NONE;
}

struct parsed_name_value
{
	char *name;
	char *value;
	int lineno;
	struct list_head list;
};

/*
 * Read a file representing all of the data in an account.
 * We generate this file when editing an account, and parse it back
 * after a user has edited it.
 *
 * Multiline values are accepted (though they may not be supported by
 * lastpass in all cases).
 *
 * Once the "Notes:" label is encountered, everything else is concatenated
 * into the note.
 *
 * Name: text0
 * URL: text1
 * [...]
 * Notes:
 * notes text here
 */
static void parse_account_file(FILE *input, enum note_type note_type,
			       struct list_head *list_head)
{
	_cleanup_free_ char *line = NULL;
	ssize_t read;
	size_t len = 0;
	char *name, *delim, *value = NULL;
	bool parsing_notes = false;
	int ret;
	int lineno = 0;

	struct parsed_name_value *current = NULL;

	/* parse label: [value] */
	while ((read = getline(&line, &len, input)) != -1) {
		lineno++;

		line = trim(line);
		delim = strchr(line, ':');
		if (!delim) {
			/* non keyed strings go to existing field (if any) */
			if (current)
				xstrappendf(&current->value, "\n%s", line);
			continue;
		}

		name = xstrndup(line, delim - line);
		value = xstrdup(delim + 1);

		/*
		 * If this is a known notetype, append any non-existent
		 * keys to the existing field.  For example, Proc-Type
		 * in the ssh private key field goes into private key,
		 * not a Proc-Type field.
		 */
		if (note_type != NOTE_TYPE_NONE &&
		    !note_has_field(note_type, name) && current &&
		    note_field_is_multiline(note_type, current->name)) {
			xstrappendf(&current->value, "\n%s", line);

			free(name);
			free(value);
			continue;
		}

		if (!strcmp(name, "Notes")) {
			parsing_notes = true;
			free(name);
			free(value);
			break;
		}

		current = new0(struct parsed_name_value, 1);
		current->name = name;
		current->value = value;
		current->lineno = lineno;
		list_add_tail(&current->list, list_head);
	}

	if (!parsing_notes)
		return;

	/* everything else goes into notes section */
	value = NULL;
	len = 0;
	ret = read_file_buf(input, &value, &len);
	if (ret)
		return;

	if (len > MAX_NOTE_LEN) {
		die("Maximum note length is %lu bytes (was %lu)",
		    MAX_NOTE_LEN, len);
	}

	current = new0(struct parsed_name_value, 1);
	current->name = xstrdup("Notes");
	current->value = value;
	current->lineno = lineno;
	list_add_tail(&current->list, list_head);
}

static void read_account_file(FILE *input, struct account *account,
			      unsigned char key[KDF_HASH_LEN])
{
	LIST_HEAD(fields);
	struct parsed_name_value *entry, *tmp;

	parse_account_file(input, get_note_type(account), &fields);

	list_for_each_entry_safe(entry, tmp, &fields, list) {
		assign_account_value(account, entry->name, entry->value,
				     entry->lineno, key);
		free(entry->name);
		free(entry->value);
		list_del(&entry->list);
		free(entry);
	}
}

static
struct field *add_default_field(struct account *account,
			        const char *field_name,
			        unsigned char key[KDF_HASH_LEN])
{
	struct field *editable_field = NULL;
	bool found = false;

	list_for_each_entry(editable_field, &account->field_head, list) {
		if (!strcmp(editable_field->name, field_name)) {
			found = true;
			break;
		}
	}
	if (found)
		return editable_field;

	editable_field = new0(struct field, 1);
	editable_field->type = xstrdup("text");
	editable_field->name = xstrdup(field_name);
	field_set_value(account, editable_field, xstrdup(""), key);

	list_add_tail(&editable_field->list, &account->field_head);
	return editable_field;
}

static void add_default_fields(struct account *account,
			       enum note_type note_type,
			       unsigned char key[KDF_HASH_LEN])
{
	int i;
	struct note_template *tmpl;

	if (note_type <= NOTE_TYPE_NONE || note_type >= NUM_NOTE_TYPES)
		return;

	/*
	 * Add a new, empty field for any label in the template which
	 * does not already exist in the account.
	 */
	tmpl = &note_templates[note_type];
	for (i=0; tmpl->fields[i]; i++) {
		/*
		 * ... but skip these: they are already handled by the
		 * collapse code.
		 */
		if (!strcmp(tmpl->fields[i], "Username"))
			continue;
		if (!strcmp(tmpl->fields[i], "Password"))
			continue;

		add_default_field(account, tmpl->fields[i], key);
	}
}

static int write_account_file(FILE *fp, struct account *account,
			      unsigned char key[KDF_HASH_LEN])
{
	struct field *editable_field = NULL;
	enum note_type note_type;

#define write_field(title, field) do { \
	if (fprintf(fp, "%s: %s\n", title, field) < 0) \
		return -errno; \
	} while (0)

	write_field("Name", account->fullname);

	note_type = get_note_type(account);

	if (account->is_app) {
		struct app *app = account_to_app(account);

		write_field("Application", app->appname);
	} else if (note_type != NOTE_TYPE_NONE) {
		add_default_fields(account, note_type, key);
	} else {
		write_field("URL", account->url);
		write_field("Username", account->username);
		write_field("Password", account->password);
	}

	list_for_each_entry(editable_field, &account->field_head, list) {
		write_field(editable_field->name, editable_field->value);
	}

	if (account->pwprotect) {
		write_field("Reprompt", "Yes");
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

	struct share *old_share = editable->share;

	notes_expansion = notes_expand(editable);
	if (notes_expansion) {
		notes_collapsed = editable;
		editable = notes_expansion;
	} else if (choice == EDIT_FIELD)
		die("Editing fields of entries that are not secure notes is currently not supported.");

	switch(choice)
	{
	case EDIT_USERNAME:
		value = editable->username;
		break;
	case EDIT_PASSWORD:
		value = editable->password;
		break;
	case EDIT_URL:
		value = editable->url;
		break;
	case EDIT_NAME:
		value = editable->fullname;
		break;
	case EDIT_FIELD:
		editable_field = add_default_field(editable, field, key);
		value = editable_field->value;
		break;
	case EDIT_NOTES:
		value = editable->note;
		break;
	default:
		value = NULL;
	}

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
			if (write_account_file(tmpfile, editable, key))
				die_unlink_errno("fprintf", tmppath, tmpdir);
		} else {
			if (fprintf(tmpfile, "%s\n", value) < 0)
				die_unlink_errno("fprintf", tmppath, tmpdir);
		}
		fclose(tmpfile);

		xasprintf(&editcmd, "${VISUAL:-${EDITOR:-vi}} '%s'", tmppath);
		if (system(editcmd) < 0)
			die_unlink_errno("system($VISUAL)", tmppath, tmpdir);

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
		read_account_file(tmpfile, editable, key);
		value = NULL;
	} else {
		ret = read_file_buf(tmpfile, &value, &len);
		if (ret)
			die_unlink_errno("fread(tmpfile)", tmppath, tmpdir);
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
		if (!value || !strlen(value)) {
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
		account_set_fullname(editable, xstrdup(notes_collapsed->fullname), key);
		editable->pwprotect = notes_collapsed->pwprotect;
		account_free(notes_collapsed);
	}

	account_assign_share(blob, editable, key);
	if (old_share != editable->share) {
		die("Use lpass mv to move items to/from shared folders");
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
		     bool is_app,
		     enum note_type note_type,
		     unsigned char key[KDF_HASH_LEN])
{
	struct app *app;
	struct account *account;

	if (note_type != NOTE_TYPE_NONE &&
	    choice != EDIT_NOTES && choice != EDIT_ANY) {
		die("Note type may only be used with secure notes");
	}

	if (is_app) {
		app = new_app();
		account = &app->account;
	} else {
		account = new_account();
	}

	account->id = xstrdup("0");
	account->attachkey = xstrdup("");
	account->attachkey_encrypted = xstrdup("");
	account_set_password(account, xstrdup(""), key);
	account_set_fullname(account, xstrdup(name), key);
	account_set_username(account, xstrdup(""), key);
	account_set_note(account, xstrdup(""), key);
	if (choice == EDIT_NOTES || note_type != NOTE_TYPE_NONE) {
		account->url = xstrdup("http://sn");
	} else {
		account->url = xstrdup("");
	}
	account_assign_share(blob, account, key);
	list_add(&account->list, &blob->account_head);

	if (note_type != NOTE_TYPE_NONE) {
		char *note_type_str = NULL;
		xasprintf(&note_type_str, "NoteType:%s\n",
			  notes_get_name(note_type));
		account_set_note(account, note_type_str, key);
	}

	return edit_account(session, blob, sync, account, choice, field,
			    non_interactive, key);
}
