/*
 * command for exporting vault entries into CSV format
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
#include "blob.h"
#include "endpoints.h"
#include "agent.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

struct field_selection {
	const char *name;
	struct list_head list;
};

static void parse_field_arg(char *arg, struct list_head *head)
{
	char *token;
	for (token = strtok(arg, ","); token; token = strtok(NULL, ",")) {
		struct field_selection *sel = new0(struct field_selection, 1);
		sel->name = token;
		list_add_tail(&sel->list, head);
	}
}

static void print_csv_cell(const char *cell, bool is_last)
{
	const char *ptr;
	bool needs_quote = false;

	cell = cell == NULL ? "" : cell;

	/* decide if we need quoting */
	for (ptr = cell; *ptr; ptr++) {
		if (*ptr == '"' || *ptr == ',' || *ptr == '\n' || *ptr == '\r') {
			needs_quote = true;
			break;
		}
	}

	if (needs_quote)
		putchar('"');

	for (ptr = cell; *ptr; ptr++) {
		putchar(*ptr);
		if (*ptr == '"')
			putchar('"');
	}

	if (needs_quote)
		putchar('"');

	if (is_last)
		printf("\r\n");
	else
		printf(",");
}

void print_csv_field(struct account *account, const char *field_name,
		     bool is_last)
{
	_cleanup_free_ char *share_group = NULL;
	char *groupname = account->group;

#define OUTPUT_FIELD(name, value, is_last) \
	do { \
		if (!strcmp(field_name, name)) { \
			print_csv_cell(value, is_last); \
			return; \
		} \
	} while(0)

	OUTPUT_FIELD("url", account->url, is_last);
	OUTPUT_FIELD("username", account->username, is_last);
	OUTPUT_FIELD("password", account->password, is_last);
	OUTPUT_FIELD("extra", account->note, is_last);
	OUTPUT_FIELD("name", account->name, is_last);
	OUTPUT_FIELD("fav", bool_str(account->fav), is_last);
	OUTPUT_FIELD("id", account->id, is_last);
	OUTPUT_FIELD("group", account->group, is_last);
	OUTPUT_FIELD("fullname", account->fullname, is_last);
	OUTPUT_FIELD("last_touch", account->last_touch, is_last);
	OUTPUT_FIELD("last_modified_gmt", account->last_modified_gmt, is_last);
	OUTPUT_FIELD("attachpresent", bool_str(account->attachpresent), is_last);

	if (!strcmp(field_name, "grouping")) {
		if (account->share) {
			xasprintf(&share_group, "%s\\%s",
				  account->share->name, account->group);

			/* trim trailing backslash if no subfolder */
			if (!strlen(account->group))
				share_group[strlen(share_group)-1] = '\0';

			groupname = share_group;
		}
		print_csv_cell(groupname, is_last);
		return;
	}

	/* unknown field, just return empty string */
	print_csv_cell("", is_last);
}

int cmd_export(int argc, char **argv)
{
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{"fields", required_argument, NULL, 'f'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	enum blobsync sync = BLOB_SYNC_AUTO;
	struct account *account;
	const char *default_fields[] = {
		"url", "username", "password", "extra",
		"name", "grouping", "fav"
	};

	LIST_HEAD(field_list);

	while ((option = getopt_long(argc, argv, "", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case 'f':
				parse_field_arg(optarg, &field_list);
				break;
			case '?':
			default:
				die_usage(cmd_export_usage);
		}
	}

	if (list_empty(&field_list)) {
		for (unsigned int i = 0; i < ARRAY_SIZE(default_fields); i++) {
			struct field_selection *sel = new0(struct field_selection, 1);
			sel->name = default_fields[i];
			list_add_tail(&sel->list, &field_list);
		}
	}

	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	struct field_selection *field_sel, *tmp;

	init_all(sync, key, &session, &blob);

	/* reprompt once if any one account is password protected */
	list_for_each_entry(account, &blob->account_head, list) {
		if (account->pwprotect) {
			unsigned char pwprotect_key[KDF_HASH_LEN];
			if (!agent_load_key(pwprotect_key))
				die("Could not authenticate for protected entry.");
			if (memcmp(pwprotect_key, key, KDF_HASH_LEN))
				die("Current key is not on-disk key.");
			break;
		}
	}

	struct field_selection *last_entry =
		list_last_entry_or_null(&field_list, struct field_selection, list);

	/* header */
	list_for_each_entry(field_sel, &field_list, list) {
		print_csv_cell(field_sel->name, field_sel == last_entry);
	}

	/* entries */
	list_for_each_entry(account, &blob->account_head, list) {

		/* skip groups */
		if (!strcmp(account->url, "http://group"))
			continue;

		list_for_each_entry(field_sel, &field_list, list) {
			print_csv_field(account, field_sel->name,
					field_sel == last_entry);
		}
		lastpass_log_access(sync, session, key, account);
	}

	list_for_each_entry_safe(field_sel, tmp, &field_list, list) {
		free(field_sel);
	}

	session_free(session);
	blob_free(blob);
	return 0;
}
