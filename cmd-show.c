/*
 * Copyright (c) 2014 LastPass. All Rights Reserved.
 *
 *
 */

#include "cmd.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "agent.h"
#include "kdf.h"
#include "endpoints.h"
#include "clipboard.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

int cmd_show(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	_cleanup_free_ char *value = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"all", no_argument, NULL, 'A'},
		{"username", no_argument, NULL, 'U'},
		{"password", no_argument, NULL, 'P'},
		{"url", no_argument, NULL, 'L'},
		{"field", required_argument, NULL, 'F'},
		{"id", no_argument, NULL, 'I'},
		{"name", no_argument, NULL, 'N'},
		{"notes", no_argument, NULL, 'O'},
		{"clip", no_argument, NULL, 'c'},
		{0, 0, 0, 0}
	};
	char option;
	int option_index;
	enum { ALL, USERNAME, PASSWORD, URL, FIELD, ID, NAME, NOTES } choice = ALL;
	_cleanup_free_ char *field = NULL;
	struct account *notes_expansion = NULL;
	char *name;
	struct account *found = NULL;
	enum blobsync sync = BLOB_SYNC_AUTO;
	bool clip = false;

	while ((option = getopt_long(argc, argv, "c", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'A':
				choice = ALL;
				break;
			case 'U':
				choice = USERNAME;
				break;
			case 'P':
				choice = PASSWORD;
				break;
			case 'L':
				choice = URL;
				break;
			case 'F':
				choice = FIELD;
				field = xstrdup(optarg);
				break;
			case 'I':
				choice = ID;
				break;
			case 'N':
				choice = NAME;
				break;
			case 'O':
				choice = NOTES;
				break;
			case 'c':
				clip = true;
				break;
			case '?':
			default:
				die_usage(cmd_show_usage);
		}
	}

	if (argc - optind != 1)
		die_usage(cmd_show_usage);
	name = argv[optind];

	init_all(sync, key, &session, &blob);

	found = find_unique_account(blob, name);
	if (!found)
		die("Could not find specified account '%s'.", name);

	if (found->pwprotect) {
		unsigned char pwprotect_key[KDF_HASH_LEN];
		if (!agent_load_key(pwprotect_key))
			die("Could not authenticate for protected entry.");
		if (memcmp(pwprotect_key, key, KDF_HASH_LEN))
			die("Current key is not on-disk key.");
	}

	lastpass_log_access(sync, session, key, found);

	notes_expansion = notes_expand(found);
	if (notes_expansion)
		found = notes_expansion;

	if (choice == FIELD) {
		struct field *found_field;
		for (found_field = found->field_head; found_field; found_field = found_field->next) {
			if (!strcmp(found_field->name, field))
				break;
		}
		if (!found_field)
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

	if (clip)
		clipboard_open();

	if (choice == ALL) {
		account_print_all(found);
	} else {
		if (!value)
			die("Programming error.");
		printf("%s", value);
		if (!clip)
			putchar('\n');
	}

	account_free(notes_expansion);
	session_free(session);
	blob_free(blob);
	return 0;
}
