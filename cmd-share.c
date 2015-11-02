/*
 * commands to manipulate shared folders
 *
 * Copyright (C) 2015 LastPass.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * In addition, as a special exception, the copyright holders grant you
 * additional permission to link or combine this program with the OpenSSL
 * library and distribute the resulting work.  See the LICENSE.OpenSSL file
 * in this distribution for more details.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
 */
#include "cmd.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "agent.h"
#include "kdf.h"
#include "endpoints.h"
#include "clipboard.h"
#include "upload-queue.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

struct share_args {
	struct session *session;
	struct blob *blob;
	enum blobsync sync;
	unsigned char key[KDF_HASH_LEN];
	const char *sharename;
	struct share *share;

	bool read_only;
	bool set_read_only;
	bool admin;
	bool set_admin;
	bool hide_passwords;
	bool set_hide_passwords;
};

#define share_userls_usage "userls SHARE"
#define share_useradd_usage "useradd [--read_only=[true|false] --hidden=[true|false] --admin=[true|false] SHARE USERNAME"
#define share_usermod_usage "usermod [--read_only=[true|false] --hidden=[true|false] --admin=[true|false] SHARE USERNAME"
#define share_userdel_usage "userdel SHARE USERNAME"
#define share_create_usage "create SHARE"
#define share_rm_usage "rm SHARE"

static char *checkmark(int x) {
	return (x) ? "x" : "_";
}

static int share_userls(int argc, char **argv, struct share_args *args)
{
	UNUSED(argv);
	struct share_user *user;
	char name[40];
	LIST_HEAD(users);
	bool has_groups = false;

	if (argc)
		die_usage(cmd_share_usage);

	if (!args->share)
		die("Share %s not found.", args->sharename);

	if (lastpass_share_getinfo(args->session, args->share->id, &users))
		die("Unable to access user list for share %s\n",
		    args->sharename);

	terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "%-40s %6s %6s %6s %6s %6s" TERMINAL_RESET "\n",
	       "User", "RO", "Admin", "Hide", "OutEnt", "Accept");

	list_for_each_entry(user, &users, list) {
		if (user->is_group) {
			has_groups = true;
			continue;
		}

		if (user->realname) {
			snprintf(name, sizeof(name), "%s <%s>",
				 user->realname, user->username);
		} else {
			snprintf(name, sizeof(name), "%s", user->username);
		}

		terminal_printf("%-40s %6s %6s %6s %6s %6s"
				"\n",
				name,
				checkmark(user->read_only),
				checkmark(user->admin),
				checkmark(user->hide_passwords),
				checkmark(user->outside_enterprise),
				checkmark(user->accepted));
	}

	if (!has_groups)
		return 0;


	terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "%-40s %6s %6s %6s %6s %6s"
			TERMINAL_RESET "\n",
			"Group", "RO", "Admin", "Hide", "OutEnt", "Accept");

	list_for_each_entry(user, &users, list) {
		if (!user->is_group)
			continue;

		terminal_printf("%-40s %6s %6s %6s %6s %6s"
				"\n",
				user->username,
				checkmark(user->read_only),
				checkmark(user->admin),
				checkmark(user->hide_passwords),
				checkmark(user->outside_enterprise),
				checkmark(user->accepted));
	}
	return 0;
}

static int share_useradd(int argc, char **argv, struct share_args *args)
{
	struct share_user new_user = {
		.read_only = args->read_only,
		.hide_passwords = args->hide_passwords,
		.admin = args->admin
	};

	if (argc != 1)
		die_usage(cmd_share_usage);

	new_user.username = argv[0];
	lastpass_share_user_add(args->session, args->share, &new_user);
	return 0;
}

static
struct share_user *get_user_from_share(struct session *session,
				       struct share *share,
				       const char *username)
{
	struct share_user *tmp, *found = NULL;
	LIST_HEAD(users);

	if (lastpass_share_getinfo(session, share->id, &users))
		die("Unable to access user list for share %s\n", share->name);

	list_for_each_entry(tmp, &users, list) {
		if (strcmp(tmp->username, username) == 0) {
			found = tmp;
			break;
		}
	}
	if (!found)
		die("Unable to find user %s in the user list\n",
		    username);

	return found;
}


static int share_usermod(int argc, char **argv, struct share_args *args)
{
	struct share_user *user;

	if (argc != 1)
		die_usage(cmd_share_usage);

	user = get_user_from_share(args->session, args->share, argv[0]);

	if (args->set_read_only)
		user->read_only = args->read_only;
	if (args->set_hide_passwords)
		user->hide_passwords = args->hide_passwords;
	if (args->set_admin)
		user->admin = args->admin;

	lastpass_share_user_mod(args->session, args->share, user);
	return 0;
}

static int share_userdel(int argc, char **argv, struct share_args *args)
{
	struct share_user *found;

	if (argc != 1)
		die_usage(cmd_share_usage);

	found = get_user_from_share(args->session, args->share, argv[0]);
	lastpass_share_user_del(args->session, args->share->id, found);
	return 0;
}

static int share_create(int argc, char **argv, struct share_args *args)
{
	if (argc != 0)
		die_usage(cmd_share_usage);

	UNUSED(argv);

	lastpass_share_create(args->session, args->sharename);
	return 0;
}

static int share_rm(int argc, char **argv, struct share_args *args)
{
	if (argc != 0)
		die_usage(cmd_share_usage);

	UNUSED(argv);

	lastpass_share_delete(args->session, args->share);
	return 0;
}

#define SHARE_CMD(name) { #name, "share " share_##name##_usage, share_##name }
static struct {
	const char *name;
	const char *usage;
	int (*cmd)(int, char **, struct share_args *share);
} share_commands[] = {
	SHARE_CMD(userls),
	SHARE_CMD(useradd),
	SHARE_CMD(usermod),
	SHARE_CMD(userdel),
	SHARE_CMD(create),
	SHARE_CMD(rm),
};
#undef SHARE_CMD

int cmd_share(int argc, char **argv)
{
	char *subcmd;

	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{"read-only", required_argument, NULL, 'r'},
		{"hidden", required_argument, NULL, 'H'},
		{"admin", required_argument, NULL, 'a'},
		{0, 0, 0, 0}
	};

	struct share_args args = {
		.sync = BLOB_SYNC_AUTO,
		.read_only = true,
		.hide_passwords = true,
	};

	/*
	 * Parse out all option commands for all subcommands, and store
	 * them in the share_args struct.
	 *
	 * All commands have at least subcmd and sharename non-option args.
	 * Additional non-option commands are passed as argc/argv to the
	 * sub-command.
	 *
	 * Although we look up the share based on the supplied sharename,
	 * it may not exist, in the case of commands such as 'add'.  Subcmds
	 * should check args.share before using it.
	 */
	int option;
	int option_index;
	while ((option = getopt_long(argc, argv, "S:C:r:H:a:", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				args.sync = parse_sync_string(optarg);
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case 'r':
				args.read_only = parse_bool_arg_string(optarg);
				args.set_read_only = true;
				break;
			case 'H':
				args.hide_passwords =
					parse_bool_arg_string(optarg);
				args.set_hide_passwords = true;
				break;
			case 'a':
				args.admin = parse_bool_arg_string(optarg);
				args.set_admin = true;
				break;
			case '?':
			default:
				die_usage(cmd_share_usage);
		}
	}

	if (argc - optind < 2)
		die_usage(cmd_share_usage);

	subcmd = argv[optind++];
	args.sharename = argv[optind++];

	init_all(args.sync, args.key, &args.session, &args.blob);

	if (strcmp(subcmd, "create") != 0)
		args.share = find_unique_share(args.blob, args.sharename);

	for (unsigned int i=0; i < ARRAY_SIZE(share_commands); i++) {
		if (strcmp(subcmd, share_commands[i].name) == 0) {
			share_commands[i].cmd(argc - optind, &argv[optind],
					      &args);
		}
	}

	session_free(args.session);
	blob_free(args.blob);
	return 0;
}
