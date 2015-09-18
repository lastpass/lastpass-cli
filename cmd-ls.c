/*
 * Copyright (c) 2014-2015 LastPass.
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

#define MODIFIED_TAG	"m"
#define TOUCHED_TAG	"t"

static bool long_listing = false;

struct node {
	char *name;
	struct account *account;
	bool shared;

	struct node *first_child;
	struct node *next_sibling;
};

static char* format_timestamp(char* timestamp, char* tag, bool utc)
{
	char*  result    = NULL;
	time_t ts_time_t = (time_t) strtoul(timestamp, NULL, 10);

	if (ts_time_t == 0) {
		result = (char*) calloc(1, 1);
	} else {
		char temp[24];
		struct tm* ts_tm;
		if (utc) {
			ts_tm = gmtime(&ts_time_t);
		} else {
			ts_tm = localtime(&ts_time_t);
		}
		strftime(temp, sizeof (temp), "%Y.%m.%d-%H:%M:%S", ts_tm);
		xasprintf(&result, "[%s: %s]", tag, temp);
	}

	return (result);
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
			if (node->account)
				if (long_listing) {
					char* last_mod   = format_timestamp(node->account->last_modified_gmt, MODIFIED_TAG, true);
					char* last_touch = format_timestamp(node->account->last_touch,        TOUCHED_TAG,  false);
					terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "%s" TERMINAL_NO_BOLD " [id: %s]" TERMINAL_FG_CYAN " %s %s" TERMINAL_RESET "\n", node->name, node->account->id, last_mod, last_touch);
				} else
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

	while ((option = getopt_long(argc, argv, "l", long_options, &option_index)) != -1) {
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
			if (long_listing) {
				char* last_mod   = format_timestamp(account->last_modified_gmt, MODIFIED_TAG, true);
				char* last_touch = format_timestamp(account->last_touch,        TOUCHED_TAG,  false);
				printf("%s [id: %s] %s %s\n", fullname, account->id, last_mod, last_touch);
				free(last_mod);
				free(last_touch);
			} else
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
