/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "cmd.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "agent.h"
#include "upload-queue.h"
#include "endpoints.h"
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>

int cmd_logout(int argc, char **argv)
{
	static struct option long_options[] = {
		{"force", no_argument, NULL, 'f'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	bool force = false;
	struct session *session = NULL;
	unsigned char key[KDF_HASH_LEN];

	while ((option = getopt_long(argc, argv, "f", long_options, &option_index)) != -1) {
		switch (option) {
			case 'f':
				force = true;
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case '?':
			default:
				die_usage(cmd_logout_usage);
		}
	}
	if (optind < argc)
		die_usage(cmd_logout_usage);

	if (!config_exists("verify"))
		die("Not currently logged in.");

	if (!force && !ask_yes_no(true, "Are you sure you would like to log out?")) {
		terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "Log out" TERMINAL_RESET ": aborted.\n");
		return 1;
	}

	init_all(0, key, &session, NULL);

	if (!config_unlink("verify") || !config_unlink("username") || !config_unlink("session_sessionid") || !config_unlink("iterations"))
		die_errno("could not log out.");
	config_unlink("blob");
	config_unlink("session_token");
	config_unlink("session_uid");
	config_unlink("session_privatekey");
	config_unlink("plaintext_key");
	agent_kill();
	upload_queue_kill();
	lastpass_logout(session);
	terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "Log out" TERMINAL_RESET ": complete.\n");
	return 0;
}
