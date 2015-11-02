/*
 * command for making copies of vault entries
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
#include "cmd.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "kdf.h"
#include "blob.h"
#include "endpoints.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>

int cmd_duplicate(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	char *name;
	enum blobsync sync = BLOB_SYNC_AUTO;
	struct account *found, *new;
	struct field *field, *copy_field;

	while ((option = getopt_long(argc, argv, "", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case '?':
			default:
				die_usage(cmd_duplicate_usage);
		}
	}

	if (argc - optind != 1)
		die_usage(cmd_duplicate_usage);
	name = argv[optind];

	init_all(sync, key, &session, &blob);

	found = find_unique_account(blob, name);
	if (!found)
		die("Could not find specified account '%s'.", name);

	new = new_account();
	new->share = found->share;
	new->id = xstrdup("0");
	account_set_name(new, xstrdup(found->name), key);
	account_set_group(new, xstrdup(found->group), key);
	account_set_username(new, xstrdup(found->username), key);
	account_set_password(new, xstrdup(found->password), key);
	account_set_note(new, xstrdup(found->note), key);
	new->fullname = xstrdup(found->fullname);
	new->url = xstrdup(found->url);
	new->pwprotect = found->pwprotect;

	list_for_each_entry(field, &found->field_head, list) {
		copy_field = new0(struct field, 1);
		copy_field->type = xstrdup(field->type);
		copy_field->name = xstrdup(field->name);
		field_set_value(found, copy_field, xstrdup(field->value), key);
		copy_field->checked = field->checked;
		list_add_tail(&copy_field->list, &new->field_head);
	}

	list_add(&new->list, &blob->account_head);

	lastpass_update_account(sync, key, session, new, blob);
	blob_save(blob, key);

	session_free(session);
	blob_free(blob);
	return 0;
}
