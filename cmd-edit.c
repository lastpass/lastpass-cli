/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "cmd.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "kdf.h"
#include "endpoints.h"
#include "agent.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

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

int cmd_edit(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"username", no_argument, NULL, 'u'},
		{"password", no_argument, NULL, 'p'},
		{"url", no_argument, NULL, 'L'},
		{"field", required_argument, NULL, 'F'},
		{"name", no_argument, NULL, 'N'},
		{"notes", no_argument, NULL, 'O'},
		{"non-interactive", no_argument, NULL, 'X'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	enum { NONE, USERNAME, PASSWORD, URL, FIELD, NAME, NOTES } choice = NONE;
	_cleanup_free_ char *field = NULL;
	_cleanup_free_ char *tmppath = NULL;
	_cleanup_free_ char *tmpdir = NULL;
	_cleanup_free_ char *editcmd = NULL;
	int tmpfd;
	FILE *tmpfile;
	char *name;
	char *value;
	bool non_interactive = false;
	enum blobsync sync = BLOB_SYNC_AUTO;
	struct account *editable;
	struct account *notes_expansion, *notes_collapsed = NULL;
	struct field *editable_field = NULL;
	size_t len, read;
	bool should_log_read = false;

	#define ensure_choice() if (choice != NONE) goto choice_die;
	while ((option = getopt_long(argc, argv, "up", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'u':
				ensure_choice();
				choice = USERNAME;
				break;
			case 'p':
				ensure_choice();
				choice = PASSWORD;
				break;
			case 'L':
				ensure_choice();
				choice = URL;
				break;
			case 'F':
				ensure_choice();
				choice = FIELD;
				field = xstrdup(optarg);
				break;
			case 'N':
				ensure_choice();
				choice = NAME;
				break;
			case 'O':
				ensure_choice();
				choice = NOTES;
				break;
			case 'X':
				non_interactive = true;
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case '?':
			default:
				die_usage(cmd_edit_usage);
		}
	}
	#undef ensure_choice

	if (argc - optind != 1)
		die_usage(cmd_edit_usage);
	if (choice == NONE)
		choice_die: die_usage("edit ... {--name|--username|--password|--url|--notes|--field=FIELD}");
	name = argv[optind];

	init_all(sync, key, &session, &blob);

	editable = find_unique_account(blob, name);
	if (editable) {
		if (editable->share && editable->share->readonly)
			die("%s is a readonly shared entry from %s. It cannot be edited.", editable->fullname, editable->share->name);
		should_log_read = true;
	} else {
		editable = new0(struct account, 1);
		editable->id = xstrdup("0");
		account_set_password(editable, xstrdup(""), key);
		account_set_fullname(editable, xstrdup(name), key);
		account_set_username(editable, xstrdup(""), key);
		account_set_note(editable, xstrdup(""), key);
		editable->url = xstrdup("");

		editable->next = blob->account_head;
		blob->account_head = editable;
	}
	notes_expansion = notes_expand(editable);
	if (notes_expansion) {
		notes_collapsed = editable;
		editable = notes_expansion;
	} else if (choice == FIELD)
		die("Editing fields of entries that are not secure notes is currently not supported.");

	if (choice == USERNAME)
		value = editable->username;
	else if (choice == PASSWORD)
		value = editable->password;
	else if (choice == URL)
		value = editable->url;
	else if (choice == NAME)
		value = editable->fullname;
	else if (choice == FIELD) {
		for (editable_field = editable->field_head; editable_field; editable_field = editable_field->next) {
			if (!strcmp(editable_field->name, field))
				break;
		}
		if (!editable_field) {
			editable_field = new0(struct field, 1);
			editable_field->type = xstrdup("text");
			editable_field->name = xstrdup(field);
			field_set_value(editable, editable_field, xstrdup(""), key);

			editable_field->next = editable->field_head;
			editable->field_head = editable_field;
		}
		value = editable_field->value;
	} else if (choice == NOTES)
		value = editable->note;

	if (!non_interactive) {
		if (editable->pwprotect) {
			unsigned char pwprotect_key[KDF_HASH_LEN];
			if (!agent_load_key(pwprotect_key))
				die("Could not authenticate for protected entry.");
			if (memcmp(pwprotect_key, key, KDF_HASH_LEN))
				die("Current key is not on-disk key.");
		}
		if (should_log_read)
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

	if (choice == NOTES) {
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

	if (choice == USERNAME)
		account_set_username(editable, value, key);
	else if (choice == PASSWORD)
		account_set_password(editable, value, key);
	else if (choice == URL) {
		free(editable->url);
		editable->url = value;
	} else if (choice == NAME)
		account_set_fullname(editable, value, key);
	else if (choice == NOTES)
		account_set_note(editable, value, key);
	else if (choice == FIELD) {
		if (!strlen(value)) {
			if (editable->field_head == editable_field)
				editable->field_head = editable_field->next;
			else {
				for (struct field *found = editable->field_head; found; found = found->next) {
					if (found->next == editable_field) {
						found->next = editable_field->next;
						break;
					}
				}
			}
			field_free(editable_field);
		} else
			field_set_value(editable, editable_field, value, key);
	}

	if (notes_expansion && notes_collapsed) {
		editable = notes_collapsed;
		notes_collapsed = notes_collapse(notes_expansion);
		account_free(notes_expansion);
		account_set_note(editable, xstrdup(notes_collapsed->note), key);
		if (choice == NAME)
			account_set_fullname(editable, xstrdup(notes_collapsed->fullname), key);
		account_free(notes_collapsed);
	}

	lastpass_update_account(sync, key, session, editable, blob);
	blob_save(blob, key);

	session_free(session);
	blob_free(blob);
	return 0;
}
