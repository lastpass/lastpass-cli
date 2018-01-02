/*
 * command for logging into the service
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

	if (!force && plaintext_key && !ask_yes_no(false, "You have used the --plaintext-key option. This option will greatly reduce the security of your passwords. You are advised, instead, to use the agent, whose timeout can be disabled by setting LPASS_AGENT_TIMEOUT=0. Are you sure you would like to do this?"))
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
