/*
 * Copyright (c) 2014 LastPass.
 *
 *
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

static char *pretty_field_value(struct field *field)
{
	char *value;
	if (!strcmp(field->type, "checkbox"))
		value = xstrdup(field->checked ? "Checked" : "Unchecked");
	else if (!strcmp(field->type, "radio"))
		xasprintf(&value, "%s, %s", field->value, field->checked ? "Checked" : "Unchecked");
	else
		value = xstrdup(field->value);
	return value;
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

int cmd_show(int argc, char **argv)
{
	unsigned char key[KDF_HASH_LEN];
	struct session *session = NULL;
	struct blob *blob = NULL;
	_cleanup_free_ char *value = NULL;
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"all", no_argument, NULL, 'A'},
		{"username", no_argument, NULL, 'u'},
		{"password", no_argument, NULL, 'p'},
		{"url", no_argument, NULL, 'L'},
		{"field", required_argument, NULL, 'f'},
		{"id", no_argument, NULL, 'I'},
		{"name", no_argument, NULL, 'N'},
		{"notes", no_argument, NULL, 'O'},
		{"clip", no_argument, NULL, 'c'},
		{"color", required_argument, NULL, 'C'},
		{"basic-regexp", no_argument, NULL, 'G'},
		{"fixed-strings", no_argument, NULL, 'F'},
		{0, 0, 0, 0}
	};

	int option;
	int option_index;
	enum { ALL, USERNAME, PASSWORD, URL, FIELD, ID, NAME, NOTES } choice = ALL;
	_cleanup_free_ char *field = NULL;
	struct account *notes_expansion = NULL;
	char *name, *pretty_field;
	struct account *found, *last_found;
	enum blobsync sync = BLOB_SYNC_AUTO;
	bool clip = false;
	struct list_head matches;
	enum search_type search = SEARCH_EXACT_MATCH;
	int fields = ACCOUNT_NAME;

	while ((option = getopt_long(argc, argv, "cupFG", long_options, &option_index)) != -1) {
		switch (option) {
			case 'S':
				sync = parse_sync_string(optarg);
				break;
			case 'A':
				choice = ALL;
				break;
			case 'u':
				choice = USERNAME;
				break;
			case 'p':
				choice = PASSWORD;
				break;
			case 'L':
				choice = URL;
				break;
			case 'f':
				choice = FIELD;
				field = xstrdup(optarg);
				break;
			case 'G':
				search = SEARCH_BASIC_REGEX;
				break;
			case 'F':
				search = SEARCH_FIXED_SUBSTRING;
				break;
			case 'I':
				choice = ID;
				break;
			case 'N':
				choice = NAME;
				break;
			case 'O':
				choice = NOTES;
				break;
			case 'c':
				clip = true;
				break;
			case 'C':
				terminal_set_color_mode(
					parse_color_mode_string(optarg));
				break;
			case '?':
			default:
				die_usage(cmd_show_usage);
		}
	}

	if (argc - optind != 1)
		die_usage(cmd_show_usage);
	name = argv[optind];

	init_all(sync, key, &session, &blob);

	INIT_LIST_HEAD(&matches);
	switch (search) {
	case SEARCH_EXACT_MATCH:
		find_matching_accounts(blob, name, &matches);
		break;
	case SEARCH_BASIC_REGEX:
		find_matching_regex(blob, name, fields, &matches);
		break;
	case SEARCH_FIXED_SUBSTRING:
		find_matching_substr(blob, name, fields, &matches);
		break;
	}

	if (list_empty(&matches))
		die("Could not find specified account '%s'.", name);

	found = list_first_entry(&matches, struct account, match_list);
	last_found = list_last_entry(&matches, struct account, match_list);
	if (found != last_found) {
		/* Multiple matches; dump the ids and exit */
		terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "Multiple matches found.\n");
		list_for_each_entry(found, &matches, match_list)
			print_header(found);
		exit(EXIT_SUCCESS);
	}

	if (found->pwprotect) {
		unsigned char pwprotect_key[KDF_HASH_LEN];
		if (!agent_load_key(pwprotect_key))
			die("Could not authenticate for protected entry.");
		if (memcmp(pwprotect_key, key, KDF_HASH_LEN))
			die("Current key is not on-disk key.");
	}

	lastpass_log_access(sync, session, key, found);

	notes_expansion = notes_expand(found);
	if (notes_expansion)
		found = notes_expansion;

	if (choice == FIELD) {
		struct field *found_field;
		for (found_field = found->field_head; found_field; found_field = found_field->next) {
			if (!strcmp(found_field->name, field))
				break;
		}
		if (!found_field)
			die("Could not find specified field '%s'.", field);
		value = pretty_field_value(found_field);
	} else if (choice == USERNAME)
		value = xstrdup(found->username);
	else if (choice == PASSWORD)
		value = xstrdup(found->password);
	else if (choice == URL)
		value = xstrdup(found->url);
	else if (choice == ID)
		value = xstrdup(found->id);
	else if (choice == NAME)
		value = xstrdup(found->name);
	else if (choice == NOTES)
		value = xstrdup(found->note);

	if (clip)
		clipboard_open();

	if (choice == ALL) {
		print_header(found);

		if (strlen(found->username))
			terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", "Username", found->username);
		if (strlen(found->password))
			terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", "Password", found->password);
		if (strlen(found->url) && strcmp(found->url, "http://"))
			terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", "URL", found->url);
		for (struct field *found_field = found->field_head; found_field; found_field = found_field->next) {
			pretty_field = pretty_field_value(found_field);
			terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", found_field->name, pretty_field);
			free(pretty_field);
		}
		if (strlen(found->note))
			terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ":\n%s\n", "Notes", found->note);
	} else {
		if (!value)
			die("Programming error.");
		printf("%s", value);
		if (!clip)
			putchar('\n');
	}

	account_free(notes_expansion);
	session_free(session);
	blob_free(blob);
	return 0;
}
