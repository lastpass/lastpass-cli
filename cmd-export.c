/*
 * command for exporting vault entries into CSV format
 *
 * Copyright (C) 2014-2017 LastPass.
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

void print_account_to_csv_standard(struct account* account, const char* groupname)
{
		print_csv_cell(account->url, false);
		print_csv_cell(account->username, false);
		print_csv_cell(account->password, false);
		print_csv_cell(account->note, false);
		print_csv_cell(account->name, false);
		print_csv_cell(groupname, false);
		print_csv_cell(bool_str(account->fav), true);
}

void print_account_to_csv_full(struct account* account, const char* groupname)
{
		print_csv_cell(account->id, false);
		print_csv_cell(account->name, false);
		print_csv_cell(account->group, false);
		print_csv_cell(groupname, false);
		print_csv_cell(account->fullname, false);
		print_csv_cell(account->url, false);
		print_csv_cell(account->username, false);
		print_csv_cell(account->password, false);
		print_csv_cell(account->note, false);
		print_csv_cell(account->last_touch, false);
		print_csv_cell(account->last_modified_gmt, false);
		print_csv_cell(bool_str(account->fav), false);
		print_csv_cell(bool_str(account->attachpresent), true);
}

int cmd_export(int argc, char **argv)
{
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{"full", no_argument, NULL, 'f'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	enum blobsync sync = BLOB_SYNC_AUTO;
	struct account *account;
	static const char *csv_header_standard = "url,username,password,extra,name,grouping,fav\r\n";
	static const char *csv_header_full = "id,name,group,groupname,fullname,url,username,password,note,last_touch,last_modified_gmt,fav,attachpresent\r\n";
	const char *csv_header = csv_header_standard;
	int is_standard_format = 1;

	while ((option = getopt_long(argc, argv, "c", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case 'f':
				csv_header = csv_header_full;
				is_standard_format = 0;
				break;
			case '?':
			default:
				die_usage(cmd_export_usage);
		}
	}

	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
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

	printf("%s", csv_header);

	list_for_each_entry(account, &blob->account_head, list) {

		_cleanup_free_ char *share_group = NULL;
		char *groupname = account->group;

		/* skip groups */
		if (!strcmp(account->url, "http://group"))
			continue;

		if (account->share) {
			xasprintf(&share_group, "%s\\%s",
					account->share->name, account->group);

			/* trim trailing backslash if no subfolder */
			if (!strlen(account->group))
				share_group[strlen(share_group)-1] = '\0';

			groupname = share_group;
		}

		lastpass_log_access(sync, session, key, account);
		if (is_standard_format) {
			print_account_to_csv_standard(account, groupname);
			continue;
		}

		print_account_to_csv_full(account, groupname);
	}

	session_free(session);
	blob_free(blob);
	return 0;
}
