/*
 * command for listing the vault
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
#include "format.h"
#include "kdf.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static bool long_listing = false;
static bool show_mtime = true;

struct node {
	char *name;
	struct account *account;
	bool shared;

	struct list_head children;
	struct list_head list;
};

struct path_component
{
	char *component;
	struct list_head list;
};

/*
 * Tokenize path and add each component to the components list.
 * For group names, the path separator is a backslash.  The path
 * string is modified in place and the component list stores
 * pointers to the modified string.
 */
static void parse_path(char *path, struct list_head *components)
{
	char *token;
	struct path_component *pc;

	for (token = strtok(path, "\\"); token; token = strtok(NULL, "\\")) {
		pc = new0(struct path_component, 1);
		pc->component = token;
		list_add_tail(&pc->list, components);
	}
}

static void __insert_node(struct node *head,
			  struct list_head *components,
			  struct account *account)
{
	struct path_component *pc;
	struct node *child, *tmp;

	/* iteratively build a tree from all the path components */
	list_for_each_entry(pc, components, list) {
		child = NULL;
		list_for_each_entry(tmp, &head->children, list) {
			if (!strcmp(tmp->name, pc->component)) {
				child = tmp;
				break;
			}
		}
		if (!child) {
			child = new0(struct node, 1);
			child->shared= !!account->share;
			child->name = xstrdup(pc->component);
			INIT_LIST_HEAD(&child->children);
			list_add_tail(&child->list, &head->children);
		}
		head = child;
	}

	/* skip group display -- we already added the hierarchy for them */
	if (account_is_group(account))
		return;

	/* and add the site at the lowest level */
	child = new0(struct node, 1);
	child->account = account;
	child->shared= !!account->share;
	child->name = xstrdup(account->name);
	INIT_LIST_HEAD(&child->children);
	list_add_tail(&child->list, &head->children);
}

static void insert_node(struct node *head, const char *path, struct account *account)
{
	struct list_head components;
	struct path_component *pc, *tmp;
	_cleanup_free_ char *dirname = xstrdup(path);
	char *pos;

	/* remove name portion of fullname; we don't parse that */
	if (strlen(dirname) >= strlen(account->name)) {
		char *tmp = dirname + strlen(dirname) - strlen(account->name);
		if (strcmp(tmp, account->name) == 0) {
			*tmp = 0;
		}
	}

	pos = dirname;
	/* trim trailing slash */
	if (strlen(pos))
		pos[strlen(pos)-1] = 0;

	/*
	 * We are left with one of:
	 *
	 *     (none)/
	 *     groupname/
	 *     Shared-folder/
	 *     Shared-folder/groupname/
	 *
	 * If there are embedded backslashes, these are treated as folder
	 * names by parse_path().
	 */
	INIT_LIST_HEAD(&components);
	if (account->share && strlen(pos) >= strlen(account->share->name)) {
		pos[strlen(account->share->name)] = 0;
		parse_path(pos, &components);
		pos += strlen(account->share->name) + 1;
	}

	/* either '(none)/' or group/ or empty string */
	parse_path(pos, &components);

	__insert_node(head, &components, account);

	list_for_each_entry_safe(pc, tmp, &components, list) {
		list_del(&pc->list);
		free(pc);
	}
}

static void free_node(struct node *head)
{
	struct node *node, *tmp;

	if (!head)
		return;

	list_for_each_entry_safe(node, tmp, &head->children, list) {
		free_node(node);
	}
	free(head->name);
	free(head);
}

static void print_node(struct node *head, char *fmt_str, int level)
{
	struct node *node;

	list_for_each_entry(node, &head->children, list) {
		if (node->name) {
			for (int i = 0; i < level; ++i)
				printf("    ");
			if (node->account) {
				struct buffer buf;

				buffer_init(&buf);
				format_account(&buf, fmt_str, node->account);
				terminal_printf("%s\n", buf.bytes);
				free(buf.bytes);
			}
			else if (node->shared)
				terminal_printf(TERMINAL_FG_CYAN TERMINAL_BOLD "%s" TERMINAL_RESET "\n", node->name);
			else
				terminal_printf(TERMINAL_FG_BLUE TERMINAL_BOLD "%s" TERMINAL_RESET "\n", node->name);
		}
		print_node(node, fmt_str, level + 1);
	}
}

static int compare_account(const void *a, const void *b)
{
	struct account * const *acct_a = a;
	struct account * const *acct_b = b;
	_cleanup_free_ char *str1 = get_display_fullname(*acct_a);
	_cleanup_free_ char *str2 = get_display_fullname(*acct_b);

	return strcmp(str1, str2);
}

int cmd_ls(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
		{"format", required_argument, NULL, 'f'},
		{"long", no_argument, NULL, 'l'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	char *group = NULL;
	int group_len;
	char *sub;
	struct node *root;
	char *fullname;
	enum blobsync sync = BLOB_SYNC_AUTO;
	enum color_mode cmode = COLOR_MODE_AUTO;
	bool print_tree;
	struct account *account;
	_cleanup_free_ struct account **account_array = NULL;
	int i, num_accounts;
	_cleanup_free_ char *fmt_str = NULL;

	struct share *share;

	while ((option = getopt_long(argc, argv, "lmu", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'C':
				cmode = parse_color_mode_string(optarg);
				break;
			case 'f':
				fmt_str = xstrdup(optarg);
				break;
			case 'l':
				long_listing = true;
				break;
			case 'm':
				show_mtime = true;
				break;
			case 'u':
				show_mtime = false;
				break;
			case '?':
			default:
				die_usage(cmd_ls_usage);
		}
	}

	switch (argc - optind) {
		case 0:
			break;
		case 1:
			group = argv[optind];
			break;
		default:
			die_usage(cmd_ls_usage);
	}

	terminal_set_color_mode(cmode);
	print_tree = cmode == COLOR_MODE_ALWAYS ||
		     (cmode == COLOR_MODE_AUTO && isatty(fileno(stdout)));


	init_all(sync, key, &session, &blob);
	root = new0(struct node, 1);
	INIT_LIST_HEAD(&root->children);

	/* '(none)' group -> search for any without group */
	if (group && !strcmp(group, "(none)"))
		group = "";

	num_accounts = 0;
	list_for_each_entry(account, &blob->account_head, list) {
		num_accounts++;
	}
	list_for_each_entry(share, &blob->share_head, list) {
		num_accounts++;
	}

	i=0;
	account_array = xcalloc(num_accounts, sizeof(struct account *));
	list_for_each_entry(account, &blob->account_head, list) {
		account_array[i++] = account;
	}
	/* fake accounts for shares, so that empty shared folders are shown. */
	list_for_each_entry(share, &blob->share_head, list) {
		struct account *account = new_account();
		char *tmpname = NULL;

		xasprintf(&tmpname, "%s/", share->name);
		account->share = share;
		account->id = share->id;
		account_set_name(account, xstrdup(""), key);
		account_set_fullname(account, tmpname, key);
		account_set_url(account, "http://group", key);
		account_array[i++] = account;
	}
	qsort(account_array, num_accounts, sizeof(struct account *),
	      compare_account);

	if (!fmt_str) {
		xasprintf(&fmt_str,
			  TERMINAL_FG_CYAN "%s"
			  TERMINAL_FG_GREEN TERMINAL_BOLD "%%a%c"
			  TERMINAL_NO_BOLD
			  " [id: %%ai]"
			  "%s" TERMINAL_RESET,
			  (long_listing) ?
				((show_mtime) ?  "%am " : "%aU ") : "",
			  (print_tree) ? 'n' : 'N',
			  (long_listing) ? " [username: %au]" : "");
	}

	for (i=0; i < num_accounts; i++)
	{
		struct account *account = account_array[i];

		if (group) {
			sub = strstr(account->fullname, group);
			if (!sub || sub != account->fullname)
				continue;
			group_len = strlen(group);
			sub += group_len;
			if (group_len &&
			    group[group_len - 1] != '/' &&
			    sub[0] != '\0' && sub[0] != '/')
				continue;
		}

		fullname = get_display_fullname(account);

		if (print_tree)
			insert_node(root, fullname, account);
		else {
			struct buffer buf;

			buffer_init(&buf);
			format_account(&buf, fmt_str, account);
			terminal_printf("%s\n", buf.bytes);
			free(buf.bytes);
		}
		free(fullname);
	}
	if (print_tree)
		print_node(root, fmt_str, 0);

	free_node(root);
	session_free(session);
	blob_free(blob);
	return 0;
}
