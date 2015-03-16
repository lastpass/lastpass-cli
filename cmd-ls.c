/*
 * Copyright (c) 2014 LastPass.
 *
 *
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

struct node {
	char *name;
	struct account *account;
	bool shared;

	struct node *first_child;
	struct node *next_sibling;
};

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
			if (node->account)
				terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "%s" TERMINAL_NO_BOLD " [id: %s]" TERMINAL_RESET "\n", node->name, node->account->id);
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
	if (strcmp(account->group, ""))
		fullname = xstrdup(account->fullname);
	else
		xasprintf(&fullname, "(none)/%s", account->fullname);

	if (account->share) {
		free(fullname);
		xasprintf(&fullname, "%s/%s", account->share->name, account->fullname);
	}
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

	while ((option = getopt_long(argc, argv, "", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'C':
				cmode = parse_color_mode_string(optarg);
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

	for (struct account *account = blob->account_head; account; account = account->next) {
		if (group) {
			sub = strstr(account->group, group);
			if (!sub || sub != account->group)
				continue;
			group_len = strlen(group);
			sub += group_len;
			if (group[group_len - 1] != '/' && sub[0] != '\0' && sub[0] != '/')
				continue;
		}

		fullname = get_display_fullname(account);

		if (print_tree)
			insert_node(root, fullname, account);
		else
			printf("%s [id: %s]\n", fullname, account->id);

		free(fullname);
	}
	if (print_tree)
		print_node(root, -1);

	free_node(root);
	session_free(session);
	blob_free(blob);
	return 0;
}
