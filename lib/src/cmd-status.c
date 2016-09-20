/*
 * command to get the status of the LastPass agent
 *
 * Copyright (C) 2014-2016 LastPass.
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
#include "agent.h"
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

int cmd_status(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	static struct option long_options[] = {
		{"quiet", no_argument, NULL, 'q'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	bool quiet = false;
	_cleanup_free_ char *username = NULL;

	while ((option = getopt_long(argc, argv, "q", long_options, &option_index)) != -1) {
		switch (option) {
			case 'q':
				quiet = true;
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case '?':
			default:
				die_usage(cmd_status_usage);
		}
	}

	if (!agent_ask(key)) {
		if(!quiet) {
			terminal_printf(TERMINAL_FG_RED TERMINAL_BOLD "Not logged in" TERMINAL_RESET ".\n");
		}
		return 1;
	} else {
		if(!quiet) {
			username = config_read_string("username");
			terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "Logged in" TERMINAL_RESET " as " TERMINAL_UNDERLINE "%s" TERMINAL_RESET ".\n", username);
		}
		return 0;
	}
}
