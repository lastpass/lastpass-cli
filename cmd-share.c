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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include "process.h"
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

	bool specified_limit_type;
	bool whitelist;
	bool add;
	bool remove;
	bool clear;

	bool confirm_keys;
};

struct share_command {
	const char *name;
	const char *usage;
	int (*cmd)(struct share_command *cmd, int, char **,
		   struct share_args *share);
};

#define share_userls_usage "userls SHARE"
#define share_useradd_usage "useradd [--read-only=[true|false] --hidden=[true|false] --admin=[true|false] [--confirm-keys, -k] SHARE USERNAME"
#define share_usermod_usage "usermod [--read-only=[true|false] --hidden=[true|false] --admin=[true|false] SHARE USERNAME"
#define share_userdel_usage "userdel SHARE USERNAME"
#define share_create_usage "create SHARE"
#define share_limit_usage "limit [--deny|--allow] [--add|--rm|--clear] SHARE USERNAME [sites]"
#define share_rm_usage "rm SHARE"

static char *checkmark(int x) {
	return (x) ? "x" : "_";
}

static void die_share_usage(struct share_command *cmd)
{
	die_usage(cmd->usage);
}

static int share_userls(struct share_command *cmd, int argc, char **argv,
			struct share_args *args)
{
	UNUSED(argv);
	struct share_user *user;
	char name[40];
	LIST_HEAD(users);
	bool has_groups = false;

	if (argc)
		die_share_usage(cmd);

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

static int share_useradd(struct share_command *cmd, int argc, char **argv,
			 struct share_args *args)
{
	struct share_user new_user = {
		.read_only = args->read_only,
		.hide_passwords = args->hide_passwords,
		.admin = args->admin
	};

	if (argc != 1)
		die_share_usage(cmd);

	new_user.username = argv[0];
	lastpass_share_user_add(args->session, args->share, &new_user, args->confirm_keys);
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


static int share_usermod(struct share_command *cmd, int argc, char **argv,
			 struct share_args *args)
{
	struct share_user *user;

	if (argc != 1)
		die_share_usage(cmd);

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

static int share_userdel(struct share_command *cmd, int argc, char **argv,
			 struct share_args *args)
{
	struct share_user *found;

	if (argc != 1)
		die_share_usage(cmd);

	found = get_user_from_share(args->session, args->share, argv[0]);
	lastpass_share_user_del(args->session, args->share->id, found);
	return 0;
}

static void print_share_limits(struct blob *blob, struct share *share,
			       struct share_limit *limit)
{
	struct account *account;
	struct share_limit_aid *aid;
	char sitename[80];

	/* display current settings for this user */
	terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD
			"%-60s %7s %5s" TERMINAL_RESET "\n",
			"Site", "Unavail", "Avail");

	list_for_each_entry(account, &blob->account_head, list) {
		if (account->share != share)
			continue;

		bool in_list = false;
		list_for_each_entry(aid, &limit->aid_list, list) {
			if (!strcmp(aid->aid, account->id)) {
				in_list = true;
			}
		}

		bool avail = (in_list && limit->whitelist) ||
			(!in_list && !limit->whitelist);

		snprintf(sitename, sizeof(sitename),
				TERMINAL_BOLD "%-.30s" TERMINAL_NO_BOLD " [id: %s]",
				account->name, account->id);

		terminal_printf(TERMINAL_FG_GREEN
				"%-66s" TERMINAL_RESET " %8s %5s\n",
				sitename, checkmark(!avail), checkmark(avail));

	}
}


static int share_limit(struct share_command *cmd, int argc, char **argv,
		       struct share_args *args)
{
	struct share_user *found;
	struct share_limit limit;
	struct account *account;
	struct share_limit_aid *aid, *tmp;
	struct blob *blob = args->blob;
	bool changed_list_type;
	int optind;

	struct list_head potential_set;
	struct list_head matches;

	if (argc < 1)
		die_share_usage(cmd);

	found = get_user_from_share(args->session, args->share, argv[0]);
	lastpass_share_get_limits(args->session, args->share, found, &limit);

	if (!args->specified_limit_type)
		args->whitelist = limit.whitelist;

	/*
	 * prompt if we switch list type and there are entries already, in
	 * order to avoid accidentally changing a blacklist to a whitelist
	 */
	changed_list_type = args->whitelist != limit.whitelist &&
			    !list_empty(&limit.aid_list);

	if (argc == 1 && !changed_list_type) {
		/* nothing to do, just print current limits */
		print_share_limits(blob, args->share, &limit);
		return 0;
	}

	if (changed_list_type) {
		bool isok = ask_yes_no(false,
			"Supplied limit type (%s) doesn't match existing list (%s).\nContinue and switch?",
			args->whitelist ? "default deny" : "default allow",
			limit.whitelist ? "default deny" : "default allow");

		if (!isok)
			die("Aborted.");
	}

	/* add to, or subtract from current list */
	INIT_LIST_HEAD(&potential_set);
	INIT_LIST_HEAD(&matches);

	/* search only accts in this share */
	list_for_each_entry(account, &blob->account_head, list) {
		if (account->share == args->share)
			list_add(&account->match_list, &potential_set);
	}

	for (optind = 1; optind < argc; optind++) {
		char *name = argv[optind];
		find_matching_accounts(&potential_set, name, &matches);
	}

	if (args->clear) {
		list_for_each_entry_safe(aid, tmp, &limit.aid_list, list) {
			list_del(&aid->list);
			free(aid->aid);
		}
	}

	list_for_each_entry(account, &matches, match_list) {

		/* add account to share_limit */
		bool in_list = false;
		list_for_each_entry(aid, &limit.aid_list, list) {
			if (!strcmp(aid->aid, account->id)) {
				in_list = true;
				break;
			}
		}

		if ((!in_list && args->add) || args->clear) {
			struct share_limit_aid *newaid =
				new0(struct share_limit_aid, 1);
			newaid->aid = account->id;
			list_add_tail(&newaid->list, &limit.aid_list);
		}
		else if (in_list && args->remove) {
			list_del(&aid->list);
		}
	}

	limit.whitelist = args->whitelist;

	lastpass_share_set_limits(args->session, args->share, found, &limit);

	print_share_limits(blob, args->share, &limit);

	return 0;
}

static int share_create(struct share_command *cmd, int argc, char **argv,
			struct share_args *args)
{
	int ret;
	bool prepend_share;

	if (argc != 0)
		die_share_usage(cmd);

	UNUSED(argv);

	ret = lastpass_share_create(args->session, args->sharename);
	if (ret)
		die("No permission to create share");

	prepend_share = strncmp(args->sharename, "Shared-", 7);
	terminal_printf("Folder %s%s created.\n",
			(prepend_share) ? "Shared-" : "",
			args->sharename);
	return 0;
}

static int share_rm(struct share_command *cmd, int argc, char **argv,
		    struct share_args *args)
{
	if (argc != 0)
		die_share_usage(cmd);

	UNUSED(argv);

	lastpass_share_delete(args->session, args->share);
	return 0;
}

#define SHARE_CMD(name) { #name, "share " share_##name##_usage, share_##name }
static struct share_command share_commands[] = {
	SHARE_CMD(userls),
	SHARE_CMD(useradd),
	SHARE_CMD(usermod),
	SHARE_CMD(userdel),
	SHARE_CMD(create),
	SHARE_CMD(rm),
	SHARE_CMD(limit),
};
#undef SHARE_CMD

/* Display more verbose usage if no subcmd is given or matched. */
static void share_help(void)
{
	terminal_fprintf(stderr, "Usage: %s %s\n", ARGV[0], cmd_share_usage);

	for (size_t i = 0; i < ARRAY_SIZE(share_commands); ++i)
		printf("  %s %s\n", ARGV[0], share_commands[i].usage);

	exit(1);
}

int cmd_share(int argc, char **argv)
{
	char *subcmd;

	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{"read-only", required_argument, NULL, 'r'},
		{"hidden", required_argument, NULL, 'H'},
		{"admin", required_argument, NULL, 'a'},
		{"deny", no_argument, NULL, 'd'},
		{"allow", no_argument, NULL, 'w'},
		{"add", no_argument, NULL, 'A'},
		{"rm", no_argument, NULL, 'R'},
		{"clear", no_argument, NULL, 'c'},
		{"confirm-keys", no_argument, NULL, 'k'},
		{0, 0, 0, 0}
	};

	struct share_args args = {
		.sync = BLOB_SYNC_AUTO,
		.read_only = true,
		.hide_passwords = true,
		.add = true,
	};

	bool invalid_params = false;
	struct share_command *command;

	/*
	 * Parse out all option commands for all subcommands, and store
	 * them in the share_args struct.
	 *
	 * All commands have at least subcmd and sharename non-option args.
	 * Additional non-option commands are passed as argc/argv to the
	 * sub-command.
	 */
	int option;
	int option_index;
	while ((option = getopt_long(argc, argv, "S:C:r:H:a:dwARck", long_options, &option_index)) != -1) {
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
			case 'w':
				args.whitelist = true;
				args.specified_limit_type = true;
				break;
			case 'd':
				args.whitelist = false;
				args.specified_limit_type = true;
				break;
			case 'A':
				args.add = true;
				args.remove = args.clear = false;
				break;
			case 'R':
				args.remove = true;
				args.add = args.clear = false;
				break;
			case 'c':
				args.clear = true;
				args.add = args.remove = false;
				break;
			case 'k':
				args.confirm_keys = true;
				break;
			case '?':
			default:
				invalid_params = true;
		}
	}

	char *always_confirm_keys_str = getenv("LPASS_ALWAYS_CONFIRM_KEYS");
	if (always_confirm_keys_str && !strcmp(always_confirm_keys_str, "1")) {
		// Make sure we do not allow share adds without confirming the key fingerprint.
		args.confirm_keys = true;
	}

	if (argc - optind < 1)
		share_help();

	subcmd = argv[optind++];
	command = NULL;
	for (unsigned int i=0; i < ARRAY_SIZE(share_commands); i++) {
		if (strcmp(subcmd, share_commands[i].name) == 0) {
			command = &share_commands[i];
			break;
		}
	}

	if (!command)
		share_help();

	if (argc - optind < 1 || invalid_params)
		die_share_usage(command);

	args.sharename = argv[optind++];

	init_all(args.sync, args.key, &args.session, &args.blob);

	if (strcmp(subcmd, "create") != 0) {
		args.share = find_unique_share(args.blob, args.sharename);
		if (!args.share)
			die("Share %s not found.", args.sharename);
	}

	command->cmd(command, argc - optind, &argv[optind], &args);
	session_free(args.session);
	blob_free(args.blob);
	return 0;
}
