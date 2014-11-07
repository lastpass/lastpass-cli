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
	struct field **last_field;

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

	new = new0(struct account, 1);
	share_assign(found->share, &new->share);
	new->id = xstrdup("0");
	account_set_name(new, xstrdup(found->name), key);
	account_set_group(new, xstrdup(found->group), key);
	account_set_username(new, xstrdup(found->username), key);
	account_set_password(new, xstrdup(found->password), key);
	account_set_note(new, xstrdup(found->note), key);
	new->fullname = xstrdup(found->fullname);
	new->url = xstrdup(found->url);
	new->pwprotect = found->pwprotect;
	last_field = &new->field_head;
	for (struct field *field = found->field_head; field; field = field->next) {
		*last_field = new0(struct field, 1);
		(*last_field)->type = xstrdup(field->type);
		(*last_field)->name = xstrdup(field->name);
		field_set_value(found, *last_field, xstrdup(field->value), key);
		(*last_field)->checked = field->checked;
		last_field = &((*last_field)->next);
	}

	new->next = blob->account_head;
	blob->account_head = new;

	lastpass_update_account(sync, key, session, new, blob);
	blob_save(blob, key);

	session_free(session);
	blob_free(blob);
	return 0;
}
