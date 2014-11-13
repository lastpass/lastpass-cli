/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "cmd.h"
#include "kdf.h"
#include "password.h"
#include "session.h"
#include "util.h"
#include "process.h"
#include "endpoints.h"
#include "config.h"
#include "agent.h"
#include "terminal.h"
#include <getopt.h>

int cmd_login(int argc, char **argv)
{
	static struct option long_options[] = {
		{"trust", no_argument, NULL, 't'},
		{"plaintext-key", no_argument, NULL, 'P'},
		{"force", no_argument, NULL, 'f'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	bool trust = false;
	bool plaintext_key = false;
	bool force = false;
	char *username;
	_cleanup_free_ char *error = NULL;
	_cleanup_free_ char *password = NULL;
	int iterations;
	struct session *session;
	unsigned char key[KDF_HASH_LEN];
	char hex[KDF_HEX_LEN];

	while ((option = getopt_long(argc, argv, "f", long_options, &option_index)) != -1) {
	switch (option) {
		case 't':
			trust = true;
			break;
		case 'P':
			plaintext_key = true;
			break;
		case 'f':
			force = true;
			break;
		case 'C':
			terminal_set_color_mode(
				parse_color_mode_string(optarg));
			break;
		case '?':
		default:
			die_usage(cmd_login_usage);
		}
	}
	if (argc - optind != 1)
		die_usage(cmd_login_usage);

	if (!force && plaintext_key && !ask_yes_no(false, "You have used the --plaintext-key option. This option will greatly reduce the security of your passwords. You are advised, instead, to use the agent, whose timeout can be disabled by settting LPASS_AGENT_TIMEOUT=0. Are you sure you would like to do this?"))
		die("Login aborted. Try again without --plaintext-key.");

	username = argv[optind];
	iterations = lastpass_iterations(username);
	if (!iterations)
		die("Unable to fetch iteration count. Check your internet connection and be sure your username is valid.");

	do {
		free(password);
		password = password_prompt("Master Password", error, "Please enter the LastPass master password for <%s>.", username);
		if (!password)
			die("Failed to enter correct password.");

		kdf_login_key(username, password, iterations, hex);
		kdf_decryption_key(username, password, iterations, key);

		free(error);
		error = NULL;
		session = lastpass_login(username, hex, key, iterations, &error, trust);
	} while (!session_is_valid(session));

	config_unlink("plaintext_key");
	if (plaintext_key)
		config_write_buffer("plaintext_key", (char *)key, KDF_HASH_LEN);

	agent_save(username, iterations, key);

	session_save(session, key);
	session_free(session);
	session = NULL;

	terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "Success" TERMINAL_RESET ": Logged in as " TERMINAL_UNDERLINE "%s" TERMINAL_RESET ".\n", username);

	return 0;
}
