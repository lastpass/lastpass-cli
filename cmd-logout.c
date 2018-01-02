/*
 * command for logging out of LastPass
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

	session_kill();
	lastpass_logout(session);
	terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "Log out" TERMINAL_RESET ": complete.\n");
	return 0;
}
