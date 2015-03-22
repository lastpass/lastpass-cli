/*
 * Copyright (c) 2014 Ian Adam Naval <ian@ianonavy.com>. All rights reserved.
 */

#include "cmd.h"
#include "util.h"
#include "config.h"
#include "kdf.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>


int cmd_find(int argc, char **argv) {
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{0, 0, 0, 0}
	};
	char option;
	int option_index;
	char *url = NULL;
	enum blobsync sync = BLOB_SYNC_AUTO;
	struct account *found = NULL;

	while ((option = getopt_long(argc, argv, "", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case '?':
			default:
				die_usage(cmd_ls_usage);
		}
	}

	if (argc - optind == 1) {
		url = argv[optind];
	} else {
		die_usage(cmd_find_usage);
	}

	init_all(sync, key, &session, &blob);

	found = find_account_by_url(blob, url);
	if (found) {
		account_print_all(found);
	}

	init_all(sync, key, &session, &blob);
	return 0;
}