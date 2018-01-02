/*
 * command for moving vault entries
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
#include "endpoints.h"
#include "agent.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int cmd_mv(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	enum blobsync sync = BLOB_SYNC_AUTO;
	int option;
	int option_index;
	char *name;
	char *folder;
	char *new_fullname = NULL;
	struct account *account;
	struct share *old_share;

	while ((option = getopt_long(argc, argv, "SC", long_options, &option_index)) != -1) {
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
				die_usage(cmd_mv_usage);
		}
	}

	if (argc - optind != 2)
		die_usage(cmd_mv_usage);

	name = argv[optind++];
	folder = argv[optind++];

	init_all(sync, key, &session, &blob);

	account = find_unique_account(blob, name);
	if (!account) {
		die("Unable to find account %s", name);
	}

	xasprintf(&new_fullname, "%s/%s", folder, account->name);
	old_share = account->share;

	account_set_fullname(account, new_fullname, key);
	account_assign_share(blob, account, key);
	if (account->share && account->share->readonly) {
		die("You do not have access to move %s into %s",
		    account->name, account->share->name);
	}

	if (old_share != account->share) {
		/*
		 * when moving into / out of a shared folder, we need to
		 * reencrypt and make a special api call for that.
		 */
		int ret = lastpass_share_move(session, account, old_share);
		if (ret) {
			die("Move to/from shared folder failed (%d)\n", ret);
		}
		list_del(&account->list);
	} else {
		/* standard case: account just changing group name */
		lastpass_update_account(sync, key, session, account, blob);
	}
	blob_save(blob, key);

	session_free(session);
	blob_free(blob);
	return 0;
}
