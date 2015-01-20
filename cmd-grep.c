/*
 * Copyright (c) 2014 LastPass.
 *
 * cmd-grep: regex/substring search for account information
 */
#include "cmd.h"
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "agent.h"
#include "kdf.h"
#include "endpoints.h"
#include "clipboard.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <regex.h>

enum search_type
{
	SEARCH_BASIC_REGEX,
	SEARCH_FIXED_SUBSTRING,
};

static void search_accounts(struct blob *blob,
			    const void *needle,
			    int (*cmp)(const char *haystack, const void *needle),
			    struct list_head *ret_list)
{
	for (struct account *account = blob->account_head; account; account = account->next) {

		if ((cmp(account->name, needle) == 0) ||
		    (cmp(account->fullname, needle) == 0) ||
		    (cmp(account->url, needle) == 0) ||
		    (cmp(account->username, needle) == 0)) {
			list_add_tail(&account->match_list, ret_list);
			continue;
		}
	}
}

static int cmp_regex(const char *haystack, const void *needle)
{
	return regexec(needle, haystack, 0, NULL, 0);
}

/*
 * Search accounts on name, username, and url fields, adding all matches
 * into ret_list.
 *
 * @pattern is a basic regular expression.
 */
static void search_accounts_regex(struct blob *blob,
				  const char *pattern,
				  struct list_head *ret_list)
{
	regex_t regex;

	if (regcomp(&regex, pattern, 0))
		die("Invalid regex '%s'", pattern);
	search_accounts(blob, &regex, cmp_regex, ret_list);
	regfree(&regex);
}

static int cmp_fixed(const char *haystack, const void *needle)
{
	return strstr(haystack, needle) == NULL;
}

/*
 * Search accounts on name, username, and url fields, adding all matches
 * into ret_list.
 *
 * @pattern is a fixed substring.
 */
static void search_accounts_fixed(struct blob *blob,
				  const char *pattern,
				  struct list_head *ret_list)
{
	search_accounts(blob, pattern, cmp_fixed, ret_list);
}

static void print_header(struct account *found)
{
	if (found->share)
		terminal_printf(TERMINAL_FG_CYAN "%s/" TERMINAL_RESET, found->share->name);
	if (strlen(found->group))
		terminal_printf(TERMINAL_FG_BLUE "%s/" TERMINAL_BOLD "%s" TERMINAL_RESET TERMINAL_FG_GREEN " [id: %s]" TERMINAL_RESET "\n", found->group, found->name, found->id);
	else
		terminal_printf(TERMINAL_FG_BLUE TERMINAL_BOLD "%s" TERMINAL_RESET TERMINAL_FG_GREEN " [id: %s]" TERMINAL_RESET "\n", found->name, found->id);
}

int cmd_grep(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	_cleanup_free_ char *value = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"basic-regexp", no_argument, NULL, 'G'},
		{"fixed-strings", no_argument, NULL, 'F'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	struct list_head matches;
	char *pattern;
	enum blobsync sync = BLOB_SYNC_AUTO;
	enum search_type search = SEARCH_BASIC_REGEX;
	struct account *found;

	while ((option = getopt_long(argc, argv, "GF", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'G':
				search = SEARCH_BASIC_REGEX;
				break;
			case 'F':
				search = SEARCH_FIXED_SUBSTRING;
				break;
			case '?':
			default:
				die_usage(cmd_grep_usage);
		}
	}

	if (argc - optind != 1)
		die_usage(cmd_grep_usage);
	pattern = argv[optind];

	init_all(sync, key, &session, &blob);

	INIT_LIST_HEAD(&matches);

	switch (search) {
		case SEARCH_BASIC_REGEX:
			search_accounts_regex(blob, pattern, &matches);
			break;
		case SEARCH_FIXED_SUBSTRING:
			search_accounts_fixed(blob, pattern, &matches);
			break;
	}

	if (list_empty(&matches))
		die("No matches found.");

	list_for_each_entry(found, &matches, match_list)
		print_header(found);

	session_free(session);
	blob_free(blob);
	return 0;
}
