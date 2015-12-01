/*
 * command for generating passwords
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
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "kdf.h"
#include "endpoints.h"
#include "clipboard.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#define ALL_CHARS_LEN 94
#define NICE_CHARS_LEN 62
static char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";

static void update_account(char *username, char *url, char *name, enum blobsync sync, char *password)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	struct account *new = NULL, *found = NULL;
	struct account *notes_expansion, *notes_collapsed = NULL;

	init_all(sync, key, &session, &blob);

	found = find_unique_account(blob, name);
	if (found) {
		if (found->share && found->share->readonly)
			die("%s is a readonly shared entry from %s. It cannot be edited.", found->fullname, found->share->name);
		notes_expansion = notes_expand(found);
		if (notes_expansion) {
			notes_collapsed = found;
			found = notes_expansion;
		}
		account_set_password(found, xstrdup(password), key);
		if (username)
			account_set_username(found, username, key);
		if (url) {
			free(found->url);
			found->url = url;
		}
		if (notes_expansion && notes_collapsed) {
			found = notes_collapsed;
			notes_collapsed = notes_collapse(notes_expansion);
			account_free(notes_expansion);
			account_set_note(found, xstrdup(notes_collapsed->note), key);
			account_free(notes_collapsed);
		}
	} else {
		new = new_account();
		new->id = xstrdup("0");
		account_assign_share(blob, new, name);
		account_set_password(new, xstrdup(password), key);
		account_set_fullname(new, xstrdup(name), key);
		account_set_username(new, username ? username : xstrdup(""), key);
		account_set_note(new, xstrdup(""), key);
		new->url = url ? url : xstrdup("");

		list_add(&new->list, &blob->account_head);
	}

	lastpass_update_account(sync, key, session, found ? found : new, blob);
	blob_save(blob, key);

	session_free(session);
	blob_free(blob);
}

int cmd_generate(int argc, char **argv)
{
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"username", required_argument, NULL, 'U'},
		{"url", required_argument, NULL, 'L'},
		{"no-symbols", no_argument, NULL, 'X'},
		{"only", no_argument, NULL, 'O'},
		{"clip", no_argument, NULL, 'c'},
		{0, 0, 0, 0}
	};
	char option;
	int option_index;
	char *username = NULL;
	char *url = NULL;
	bool no_symbols = false;
	bool only = false;
	unsigned long length;
	char *name;
	enum blobsync sync = BLOB_SYNC_AUTO;
	_cleanup_free_ char *password = NULL;
	bool clip = false;

	while ((option = getopt_long(argc, argv, "c", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'U':
				username = xstrdup(optarg);
				break;
			case 'L':
				url = xstrdup(optarg);
				break;
			case 'X':
				no_symbols = true;
				break;
			case 'O':
				only = true;
				break;
			case 'c':
				clip = true;
				break;
			case '?':
			default:
				die_usage(cmd_generate_usage);
		}
	}

	if (argc - optind != 2)
		die_usage(cmd_generate_usage);
	name = argv[optind];
	length = strtoul(argv[optind + 1], NULL, 10);
	if (!length)
		die_usage(cmd_generate_usage);

	password = xcalloc(length + 1, 1);
	for (size_t i = 0; i < length; ++i)
		password[i] = chars[range_rand(0, no_symbols ? NICE_CHARS_LEN : ALL_CHARS_LEN)];

        if (!only)
		update_account(username, url, name, sync, password);

	if (clip)
		clipboard_open();

	printf("%s\n", password);

	return 0;
}
