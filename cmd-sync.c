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
#include "upload-queue.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int cmd_sync(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"background", no_argument, NULL, 'b'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	bool background = false;

	while ((option = getopt_long(argc, argv, "b", long_options, &option_index)) != -1) {
		switch (option) {
			case 'b':
				background = true;
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case '?':
			default:
				die_usage(cmd_sync_usage);
		}
	}

	init_all(0, key, &session, NULL);

	upload_queue_ensure_running(key, session);
	if (!background) {
		while (upload_queue_is_running())
			usleep(1000000 / 3);
	}


	session_free(session);
	blob_free(blob);
	return 0;
}
