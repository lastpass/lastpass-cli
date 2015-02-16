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
#include "agent.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>


void print_csv_cell(char *cell, bool is_last)
{
	char *ptr;
	bool needs_quote = false;

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

int cmd_export(int argc, char **argv)
{
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	enum blobsync sync = BLOB_SYNC_AUTO;
	while ((option = getopt_long(argc, argv, "c", long_options, &option_index)) != -1) {
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
				die_usage(cmd_export_usage);
		}
	}

	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	init_all(sync, key, &session, &blob);

	/* reprompt once if any one account is password protected */
	for (struct account *account = blob->account_head; account; account = account->next) {
		if (account->pwprotect) {
			unsigned char pwprotect_key[KDF_HASH_LEN];
			if (!agent_load_key(pwprotect_key))
				die("Could not authenticate for protected entry.");
			if (memcmp(pwprotect_key, key, KDF_HASH_LEN))
				die("Current key is not on-disk key.");
			break;
		}
	}

	printf("url,username,password,hostname,name,grouping\r\n");
	for (struct account *account = blob->account_head; account; account = account->next) {

		/* skip shared notes */
		if (!strcmp(account->url, "http://sn"))
			continue;

		lastpass_log_access(sync, session, key, account);
		print_csv_cell(account->url, false);
		print_csv_cell(account->username, false);
		print_csv_cell(account->password, false);
		print_csv_cell(account->fullname, false);
		print_csv_cell(account->name, false);
		print_csv_cell(account->group, true);
	}

	session_free(session);
	blob_free(blob);
	return 0;
}
