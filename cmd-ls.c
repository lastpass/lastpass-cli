/*
 * command for listing the vault
 *
 * Copyright (C) 2014-2015 LastPass.
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

	struct node *first_child;
	struct node *next_sibling;
};

static char *format_timestamp(char *timestamp, bool utc)
{
	char temp[60];
	struct tm *ts_tm;

	time_t ts_time_t = (time_t) strtoul(timestamp, NULL, 10);

	if (ts_time_t == 0)
		return xstrdup("");

	if (utc)
		ts_tm = gmtime(&ts_time_t);
	else
		ts_tm = localtime(&ts_time_t);

	strftime(temp, sizeof(temp), "%Y-%m-%d %H:%M", ts_tm);

	return xstrdup(temp);
}

static void insert_node(struct node *head, const char *path, struct account *account)
{
	char *slash = NULL;
	struct node *child;

	while (*path && (slash = strchr(path, '/')) == path)
		++path;
	if (!path)
		return;
	if (!slash) {
		child = new0(struct node, 1);
		child->account = account;
		child->shared = !!account->share;
		child->name = xstrdup(path);
		child->next_sibling = head->first_child;
		head->first_child = child;
		return;
	}

	for (child = head->first_child; child; child = child->next_sibling) {
		if (!strncmp(child->name, path, slash - path) && strlen(child->name) == (size_t)(slash - path))
			break;
	}
	if (!child) {
		child = new0(struct node, 1);
		child->shared= !!account->share;
		child->name = xstrndup(path, slash - path);
		child->next_sibling = head->first_child;
		head->first_child = child;
	}
	insert_node(child, slash + 1, account);
}

static void free_node(struct node *head)
{
	if (!head)
		return;
	for (struct node *node = head, *next_node = NULL; node; node = next_node) {
		next_node = node->next_sibling;
		free_node(node->first_child);
		free(node->name);
		free(node);
	}
}

static void print_node(struct node *head, int level)
{
	struct node *node;

	for (node = head; node; node = node->next_sibling) {
		if (node->name) {
			for (int i = 0; i < level; ++i)
				printf("    ");
			if (node->account) {
				if (long_listing) {
					_cleanup_free_ char *timestr = show_mtime ?
						format_timestamp(node->account->last_modified_gmt, true) :
						format_timestamp(node->account->last_touch, false);
					terminal_printf(TERMINAL_FG_CYAN "%s ", timestr);
				}
				terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "%s" TERMINAL_NO_BOLD " [id: %s]" TERMINAL_RESET "\n", node->name, node->account->id);
			}
			else if (node->shared)
				terminal_printf(TERMINAL_FG_CYAN TERMINAL_BOLD "%s" TERMINAL_RESET "\n", node->name);
			else
				terminal_printf(TERMINAL_FG_BLUE TERMINAL_BOLD "%s" TERMINAL_RESET "\n", node->name);
		}
		print_node(node->first_child, level + 1);
	}
}

static char *get_display_fullname(struct account *account)
{
	char *fullname = NULL;

	if (account->share || strcmp(account->group, ""))
		fullname = xstrdup(account->fullname);
	else
		xasprintf(&fullname, "(none)/%s", account->fullname);

	return fullname;
}

int cmd_ls(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"color", required_argument, NULL, 'C'},
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

	while ((option = getopt_long(argc, argv, "lmu", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'C':
				cmode = parse_color_mode_string(optarg);
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

	/* '(none)' group -> search for any without group */
	if (group && !strcmp(group, "(none)"))
		group = "";

	list_for_each_entry(account, &blob->account_head, list) {
		if (group) {
			sub = strstr(account->fullname, group);
			if (!sub || sub != account->fullname)
				continue;
			group_len = strlen(group);
			sub += group_len;
			if (group[group_len - 1] != '/' && sub[0] != '\0' && sub[0] != '/')
				continue;
		}

		fullname = get_display_fullname(account);

		if (print_tree)
			insert_node(root, fullname, account);
		else {
			if (long_listing) {
				_cleanup_free_ char *timestr = show_mtime ?
					format_timestamp(account->last_modified_gmt, true) :
					format_timestamp(account->last_touch, false);
				printf("%s ", timestr);
			}
			printf("%s [id: %s]\n", fullname, account->id);
		}

		free(fullname);
	}
	if (print_tree)
		print_node(root, -1);

	free_node(root);
	session_free(session);
	blob_free(blob);
	return 0;
}
