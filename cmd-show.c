/*
 * command to show the contents of a vault entry
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
#include "cipher.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "agent.h"
#include "kdf.h"
#include "endpoints.h"
#include "clipboard.h"
#include "format.h"
#include "json-format.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

/*
 * If a secure note field contains ascii armor, its newlines will
 * have been replaced by spaces when saving.  Undo this for
 * display purposes.  The replacement (if applicable) is done
 * in-place.
 */
static char *fix_ascii_armor(char *armor_str)
{
	char *end_header, *start_trailer, *ptr;

	/* need at least 4 "-----" strings */
	if (strlen(armor_str) < 20)
		return armor_str;

	/* look for -----BEGIN [xxx]----- and -----END [xxx]----- strings */
	if (strncmp(armor_str, "-----BEGIN", 10))
		return armor_str;

	end_header = strstr(armor_str + 10, "----- ");
	if (!end_header)
		return armor_str;

	start_trailer = strstr(end_header, "-----END");
	if (!start_trailer)
		return armor_str;

	if (strncmp(armor_str + strlen(armor_str) - 5, "-----", 5))
		return armor_str;

	/* ok, probably ascii armor, go ahead and munge it as such */
	ptr = end_header;
	while ((ptr = strchr(ptr, ' ')) != NULL) {
		if (ptr >= start_trailer)
			break;
		/* don't modify spaces after headers, e.g. encrypted keys */
		if (ptr[-1] == ':') {
			ptr++;
			continue;
		}
		*ptr = '\n';
	}
	return armor_str;
}

static char *attachment_filename(struct account *account,
				 struct attach *attach)
{
	_cleanup_free_ unsigned char *key_bin = NULL;

	if (!attach->filename ||
	    !account->attachkey ||
	    strlen(account->attachkey) != KDF_HASH_LEN * 2 ||
	    hex_to_bytes(account->attachkey, &key_bin)) {
		return xstrdup("unknown");
	}

	return cipher_aes_decrypt_base64(attach->filename, key_bin);
}

static bool attachment_is_binary(unsigned char *data, size_t len)
{
	size_t i;
	for (i = 0; i < min(len, 100); i++) {
		if (!isprint(data[i]))
			return true;
	}
	return false;
}

static void show_attachment(const struct session *session,
			    struct account *account,
			    struct attach *attach,
			    bool quiet)
{
	_cleanup_free_ unsigned char *key_bin = NULL;
	_cleanup_free_ char *result = NULL;
	_cleanup_free_ char *filename = NULL;
	int ret;
	char opt;
	char *ptext;
	size_t len;
	char *shareid = NULL;
	unsigned char *bytes = NULL;
	FILE *fp = stdout;

	if (!account->attachkey || strlen(account->attachkey) != KDF_HASH_LEN * 2)
		die("Missing attach key for account %s\n", account->name);

	if (hex_to_bytes(account->attachkey, &key_bin))
		die("Invalid attach key for account %s\n", account->name);

	if (account->share != NULL)
		shareid = account->share->id;

	filename = attachment_filename(account, attach);

	ret = lastpass_load_attachment(session, shareid, attach, &result);
	if (ret)
		die("Could not load attachment %s\n", attach->id);

	ptext = cipher_aes_decrypt_base64(result, key_bin);
	if (!ptext)
		die("Unable to decrypt attachment %s\n", attach->id);

	len = unbase64(ptext, &bytes);

	if (attachment_is_binary(bytes, len) && !quiet) {
		opt = ask_options("yns", 's',
			    "\"%s\" is a binary file, print it anyway (or save)? ",
			    filename);
		switch (opt) {
		case 'n':
			return;
		case 's':
			fp = fopen(filename, "wb");
			if (!fp)
				die("Unable to open %s\n", filename);
			break;
		default:
			break;
		}
	}
	len = fwrite(bytes, 1, len, fp);
	if (fp != stdout) {
		fprintf(stderr, TERMINAL_FG_GREEN "Wrote %zu bytes to \"%s\"\n" TERMINAL_RESET, len, filename);
		fclose(fp);
	}
}

static char *pretty_field_value(struct field *field)
{
	char *value;
	if (!strcmp(field->type, "checkbox"))
		value = xstrdup(field->checked ? "Checked" : "Unchecked");
	else if (!strcmp(field->type, "radio"))
		xasprintf(&value, "%s, %s", field->value, field->checked ? "Checked" : "Unchecked");
	else
		value = fix_ascii_armor(xstrdup(field->value));
	return value;
}

static void print_header(char *title_format, struct account *found)
{
	struct buffer buf;

	buffer_init(&buf);
	format_account(&buf, title_format, found);
	terminal_printf("%s\n", buf.bytes);
	free(buf.bytes);
}

static void print_field(char *field_format, struct account *account,
			char *name, char *value)
{
	struct buffer buf;

	buffer_init(&buf);
	format_field(&buf, field_format, account, name, value);
	terminal_printf("%s\n", buf.bytes);
	free(buf.bytes);
}

static void print_attachment(char *field_format,
			     struct account *account,
			     struct attach *attach)
{
	_cleanup_free_ char *attach_id = NULL;
	_cleanup_free_ char *filename = NULL;

	xasprintf(&attach_id, "att-%s", attach->id);
	filename = attachment_filename(account, attach);

	print_field(field_format, account, attach_id, filename);
}

static struct attach *find_attachment(struct account *account,
				      const char *attach_id)
{
	struct attach *attach = NULL;

	/* trim 'att-' off id if someone passed it */
	if (!strncmp(attach_id, "att-", 4))
		attach_id += 4;

	list_for_each_entry(attach, &account->attach_head, list) {
		if (!strcmp(attach->id, attach_id))
			return attach;
	}
	return NULL;
}


int cmd_show(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	_cleanup_free_ char *value = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"all", no_argument, NULL, 'A'},
		{"username", no_argument, NULL, 'u'},
		{"password", no_argument, NULL, 'p'},
		{"url", no_argument, NULL, 'L'},
		{"field", required_argument, NULL, 'f'},
		{"id", no_argument, NULL, 'I'},
		{"name", no_argument, NULL, 'N'},
		{"notes", no_argument, NULL, 'O'},
		{"attach", required_argument, NULL, 'a'},
		{"clip", no_argument, NULL, 'c'},
		{"color", required_argument, NULL, 'C'},
		{"basic-regexp", no_argument, NULL, 'G'},
		{"fixed-strings", no_argument, NULL, 'F'},
		{"expand-multi", no_argument, NULL, 'x'},
		{"title-format", required_argument, NULL, 't'},
		{"format", required_argument, NULL, 'o'},
		{"json", no_argument, NULL, 'j'},
		{"quiet", no_argument, NULL, 'q'},
		{0, 0, 0, 0}
	};

	int option;
	int option_index;
	enum { ALL, USERNAME, PASSWORD, URL, FIELD, ID, NAME, NOTES, ATTACH } choice = ALL;
	_cleanup_free_ char *field = NULL;
	struct account *notes_expansion = NULL;
	struct field *found_field;
	char *name, *pretty_field;
	struct account *found, *last_found, *account;
	struct app *app;
	enum blobsync sync = BLOB_SYNC_AUTO;
	bool clip = false;
	bool json = false;
	bool expand_multi = false;
	bool quiet = false;
	struct list_head matches, potential_set;
	enum search_type search = SEARCH_EXACT_MATCH;
	int fields = ACCOUNT_NAME | ACCOUNT_ID | ACCOUNT_FULLNAME;
	struct attach *attach;

	_cleanup_free_ char *title_format = NULL;
	_cleanup_free_ char *field_format = NULL;
	_cleanup_free_ char *attach_id = NULL;

	while ((option = getopt_long(argc, argv, "cupFGxtoqj", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'A':
				choice = ALL;
				break;
			case 'u':
				choice = USERNAME;
				break;
			case 'p':
				choice = PASSWORD;
				break;
			case 'L':
				choice = URL;
				break;
			case 'f':
				choice = FIELD;
				field = xstrdup(optarg);
				break;
			case 'G':
				search = SEARCH_BASIC_REGEX;
				break;
			case 'F':
				search = SEARCH_FIXED_SUBSTRING;
				break;
			case 'I':
				choice = ID;
				break;
			case 'N':
				choice = NAME;
				break;
			case 'j':
				json = true;
				break;
			case 'a':
				choice = ATTACH;
				attach_id = xstrdup(optarg);
				break;
			case 'O':
				choice = NOTES;
				break;
			case 'c':
				clip = true;
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case 'x':
				expand_multi = true;
				break;
			case 'o':
				field_format = xstrdup(optarg);
				break;
			case 't':
				title_format = xstrdup(optarg);
				break;
			case 'q':
				quiet = true;
				break;
			case '?':
			default:
				die_usage(cmd_show_usage);
		}
	}

	if (argc - optind < 1)
		die_usage(cmd_show_usage);

	if (argc - optind > 1) {
		/*
		 * if multiple search criteria supplied, go ahead
		 * and expand all matches
		 */
		expand_multi = true;
	}

	init_all(sync, key, &session, &blob);

	INIT_LIST_HEAD(&matches);
	INIT_LIST_HEAD(&potential_set);

	if (!title_format) {
		title_format = xstrdup(
			TERMINAL_FG_CYAN "%/as" TERMINAL_RESET
			TERMINAL_FG_BLUE "%/ag"
			TERMINAL_BOLD "%an" TERMINAL_RESET
			TERMINAL_FG_GREEN " [id: %ai]" TERMINAL_RESET);
	}
	if (!field_format) {
		field_format = xstrdup(
			TERMINAL_FG_YELLOW "%fn" TERMINAL_RESET ": %fv");
	}

	list_for_each_entry(account, &blob->account_head, list)
		list_add(&account->match_list, &potential_set);

	for (; optind < argc; optind++) {

		name = argv[optind];

		switch (search) {
		case SEARCH_EXACT_MATCH:
			find_matching_accounts(&potential_set, name, &matches);
			break;
		case SEARCH_BASIC_REGEX:
			find_matching_regex(&potential_set, name, fields, &matches);
			break;
		case SEARCH_FIXED_SUBSTRING:
			find_matching_substr(&potential_set, name, fields, &matches);
			break;
		}
	}

	if (list_empty(&matches))
		die("Could not find specified account(s).");

	found = list_first_entry(&matches, struct account, match_list);
	last_found = list_last_entry(&matches, struct account, match_list);
	if (found != last_found && !expand_multi) {
		/* Multiple matches; dump the ids and exit */
		terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "Multiple matches found.\n");
		list_for_each_entry(found, &matches, match_list)
			print_header(title_format, found);
		exit(EXIT_SUCCESS);
	}

	/* reprompt if necessary for any matched item */
	list_for_each_entry(found, &matches, match_list) {
		if (found->pwprotect) {
			unsigned char pwprotect_key[KDF_HASH_LEN];
			if (!agent_load_key(pwprotect_key))
				die("Could not authenticate for protected entry.");
			if (memcmp(pwprotect_key, key, KDF_HASH_LEN))
				die("Current key is not on-disk key.");
			break;
		}
	}

	if (clip)
		clipboard_open();

	if (json) {
		json_format_account_list(&matches);
		goto done;
	}

	list_for_each_entry(account, &matches, match_list) {

		found = account;
		lastpass_log_access(sync, session, key, found);

		notes_expansion = notes_expand(found);
		if (notes_expansion)
			found = notes_expansion;

		if (choice == FIELD) {
			bool has_field = false;
			list_for_each_entry(found_field, &found->field_head, list) {
				if (!strcmp(found_field->name, field)) {
					has_field = true;
					break;
				}
			}
			if (!has_field)
				die("Could not find specified field '%s'.", field);
			value = pretty_field_value(found_field);
		} else if (choice == USERNAME)
			value = xstrdup(found->username);
		else if (choice == PASSWORD)
			value = xstrdup(found->password);
		else if (choice == URL)
			value = xstrdup(found->url);
		else if (choice == ID)
			value = xstrdup(found->id);
		else if (choice == NAME)
			value = xstrdup(found->name);
		else if (choice == NOTES)
			value = xstrdup(found->note);
		else if (choice == ATTACH) {
			struct attach *attach = find_attachment(found, attach_id);
			if (!attach)
				die("Could not find specified attachment '%s'.", attach_id);
			show_attachment(session, found, attach, quiet);
		}

		if (choice == ALL) {
			print_header(title_format, found);

			if (strlen(found->username))
				print_field(field_format, found, "Username", found->username);
			if (strlen(found->password))
				print_field(field_format, found, "Password", found->password);
			if (strlen(found->url) && strcmp(found->url, "http://"))
				print_field(field_format, found, "URL", found->url);
			if (found->is_app) {
				app = account_to_app(found);
				if (strlen(app->appname))
					print_field(field_format, found, "Application", app->appname);
			}

			list_for_each_entry(found_field, &found->field_head, list) {
				pretty_field = pretty_field_value(found_field);
				print_field(field_format, found, found_field->name, pretty_field);
				free(pretty_field);
			}
			list_for_each_entry(attach, &found->attach_head, list) {
				print_attachment(field_format, found, attach);
			}
			if (found->pwprotect)
				print_field(field_format, found, "Reprompt", "Yes");
			if (strlen(found->note))
				print_field(field_format, found, "Notes", found->note);
		} else if (choice != ATTACH) {
			if (!value)
				die("Programming error.");
			printf("%s", value);
			if (!clip)
				putchar('\n');
		}

		account_free(notes_expansion);
	}
done:
	session_free(session);
	blob_free(blob);
	return 0;
}
