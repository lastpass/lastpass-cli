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
#include "blob.h"
#include "endpoints.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>

int cmd_rm(int argc, char **argv)
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
	struct account *found;

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
				die_usage(cmd_rm_usage);
		}
	}

	if (argc - optind != 1)
		die_usage(cmd_rm_usage);
	name = argv[optind];

	init_all(sync, key, &session, &blob);
	found = find_unique_account(blob, name);
	if (!found)
		die("Could not find specified account '%s'.", name);
	if (found->share && found->share->readonly)
		die("%s is a readonly shared entry from %s. It cannot be deleted.", found->fullname, found->share->name);

	if (blob->account_head == found)
		blob->account_head = found->next;
	else {
		for (struct account *account = blob->account_head; account; account = account->next) {
			if (account->next == found) {
				account->next = found->next;
				break;
			}
		}
	}

	lastpass_remove_account(sync, key, session, found, blob);
	blob_save(blob, key);
	account_free(found);

	session_free(session);
	blob_free(blob);
	return 0;
}
