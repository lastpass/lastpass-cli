/*
 * command for adding vault entries
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
#include "kdf.h"
#include "endpoints.h"
#include "agent.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int cmd_add(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"username", no_argument, NULL, 'u'},
		{"password", no_argument, NULL, 'p'},
		{"url", no_argument, NULL, 'L'},
		{"field", required_argument, NULL, 'F'},
		{"notes", no_argument, NULL, 'O'},
		{"app", no_argument, NULL, 'a'},
		{"non-interactive", no_argument, NULL, 'X'},
		{"note-type", required_argument, NULL, 'T'},
		{"color", required_argument, NULL, 'C'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	_cleanup_free_ char *field = NULL;
	char *name;
	bool non_interactive = false;
	enum blobsync sync = BLOB_SYNC_AUTO;
	enum edit_choice choice = EDIT_ANY;
	enum note_type note_type = NOTE_TYPE_NONE;
	bool is_app = false;

	#define ensure_choice() if (choice != EDIT_ANY) goto choice_die;
	while ((option = getopt_long(argc, argv, "up", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'u':
				ensure_choice();
				choice = EDIT_USERNAME;
				break;
			case 'p':
				ensure_choice();
				choice = EDIT_PASSWORD;
				break;
			case 'L':
				ensure_choice();
				choice = EDIT_URL;
				break;
			case 'F':
				ensure_choice();
				choice = EDIT_FIELD;
				field = xstrdup(optarg);
				break;
			case 'O':
				ensure_choice();
				choice = EDIT_NOTES;
				break;
			case 'X':
				non_interactive = true;
				break;
			case 'a':
				is_app = true;
				break;
			case 'T':
				note_type = parse_note_type_string(optarg);
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case '?':
			default:
				die_usage(cmd_add_usage);
		}
	}
	#undef ensure_choice

	if (argc - optind != 1)
		die_usage(cmd_add_usage);
	if (choice == EDIT_NONE)
		choice_die: die_usage("add ... {--username|--password|--url|--notes|--field=FIELD|--note-type=NOTE_TYPE}");
	name = argv[optind];

	init_all(sync, key, &session, &blob);

	return edit_new_account(session, blob, sync, name, choice, field,
				non_interactive, is_app, note_type, key);
}
