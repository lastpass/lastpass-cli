/*
 * Copyright (c) 2014-2015 LastPass.
 */
#include "cmd.h"
#include "agent.h"
#include "blob.h"
#include "session.h"
#include "util.h"
#include "process.h"
#include "terminal.h"
#include <strings.h>
#include <string.h>
#include <regex.h>

enum blobsync parse_sync_string(const char *syncstr)
{
	if (!syncstr || !strcasecmp(syncstr, "auto"))
		return BLOB_SYNC_AUTO;
	else if (!strcasecmp(syncstr, "now"))
		return BLOB_SYNC_YES;
	else if (!strcasecmp(syncstr, "no"))
		return BLOB_SYNC_NO;
	else
		die_usage("... --sync=auto|now|no");
}

enum color_mode parse_color_mode_string(const char *colormode)
{
	if (!colormode || strcmp(colormode, "auto") == 0)
		return COLOR_MODE_AUTO;
	else if (strcmp(colormode, "never") == 0)
		return COLOR_MODE_NEVER;
	else if (strcmp(colormode, "always") == 0)
		return COLOR_MODE_ALWAYS;
	else
		die_usage("... --color=auto|never|always");
}

void init_all(enum blobsync sync, unsigned char key[KDF_HASH_LEN], struct session **session, struct blob **blob)
{
	if (!agent_get_decryption_key(key))
		die("Could not find decryption key. Perhaps you need to login with `%s login`.", ARGV[0]);

	*session = sesssion_load(key);
	if (!*session)
		die("Could not find session. Perhaps you need to login with `%s login`.", ARGV[0]);

	if (blob) {
		*blob = blob_load(sync, *session, key);
		if (!*blob)
			die("Unable to fetch blob. Either your session is invalid and you need to login with `%s login`, you need to synchronize, your blob is empty, or there is something wrong with your internet connection.", ARGV[0]);
	}
}

/*
 * cmp_regex - do regex comparison with a basic regex
 */
static int cmp_regex(const char *haystack, const char *needle)
{
	return regexec((void *) needle, haystack, 0, NULL, 0);
}

/*
 * cmp_substr - do substring comparison with a fixed pattern
 */
static int cmp_substr(const char *haystack, const char *needle)
{
	return strstr(haystack, needle) == NULL;
}

static void search_accounts(struct blob *blob,
			    const void *needle,
			    int (*cmp)(const char *haystack, const char *needle),
			    int fields,
			    struct list_head *ret_list)
{
	for (struct account *account = blob->account_head; account;
	     account = account->next) {
		if (((fields & ACCOUNT_ID) && cmp(account->id, needle) == 0) ||
		    ((fields & ACCOUNT_NAME) && cmp(account->name, needle) == 0) ||
		    ((fields & ACCOUNT_FULLNAME) && cmp(account->fullname, needle) == 0) ||
		    ((fields & ACCOUNT_URL) && cmp(account->url, needle) == 0) ||
		    ((fields & ACCOUNT_USERNAME) && cmp(account->username, needle) == 0)) {
			list_add_tail(&account->match_list, ret_list);
		}
	}
}

/*
 * Search accounts on given fields, returning results into ret_list.
 *
 * @pattern - a basic regular expression
 * @fields - which fields to search on
 */
void find_matching_regex(struct blob *blob, const char *pattern,
			 int fields, struct list_head *ret_list)
{
	regex_t regex;

	if (regcomp(&regex, pattern, REG_ICASE))
		die("Invalid regex '%s'", pattern);
	search_accounts(blob, &regex, cmp_regex, fields, ret_list);
	regfree(&regex);
}

/*
 * Search accounts on name, username, and url fields, adding all matches
 * into ret_list.
 *
 * @pattern - a basic regular expression
 * @fields - which fields to search on
 */
void find_matching_substr(struct blob *blob, const char *pattern,
			  int fields, struct list_head *ret_list)
{
	search_accounts(blob, pattern, cmp_substr, fields, ret_list);
}

/*
 * Search blob for any and all accounts matching a given name.
 * Matching accounts are appended to ret_list which should be initialized
 * by the caller.
 *
 * In the case of an id match, we return only the matching id entry.
 */
void find_matching_accounts(struct blob *blob, const char *name,
			    struct list_head *ret_list)
{
	/* look for exact id match */
	for (struct account *account = blob->account_head; account; account = account->next) {
		if (strcmp(name, "0") && !strcasecmp(account->id, name)) {
			list_add_tail(&account->match_list, ret_list);
			/* if id match, stop processing */
			return;
		}
	}

	/* search for fullname or name match */
	search_accounts(blob, name, strcmp, ACCOUNT_NAME | ACCOUNT_FULLNAME,
			ret_list);
}

struct account *find_unique_account(struct blob *blob, const char *name)
{
	struct list_head matches;
	struct account *account, *last_account;

	INIT_LIST_HEAD(&matches);

	find_matching_accounts(blob, name, &matches);

	if (list_empty(&matches))
		return NULL;

	account = list_first_entry(&matches, struct account, match_list);
	last_account = list_last_entry(&matches, struct account, match_list);

	if (account != last_account)
		die("Multiple matches found for '%s'. You must specify an ID instead of a name.", name);

	return account;
}

char *pretty_field_value(struct field *field)
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

void account_print_all(struct account *account)
{
	char *pretty_field = NULL;
	if (account->share)
		terminal_printf(TERMINAL_FG_CYAN "%s/" TERMINAL_RESET, account->share->name);
	if (strlen(account->group))
		terminal_printf(TERMINAL_FG_BLUE "%s/" TERMINAL_BOLD "%s" TERMINAL_RESET TERMINAL_FG_GREEN " [id: %s]" TERMINAL_RESET "\n", account->group, account->name, account->id);
	else
		terminal_printf(TERMINAL_FG_BLUE TERMINAL_BOLD "%s" TERMINAL_RESET TERMINAL_FG_GREEN " [id: %s]" TERMINAL_RESET "\n", account->name, account->id);
	if (strlen(account->username))
		terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", "Username", account->username);
	if (strlen(account->password))
		terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", "Password", account->password);
	if (strlen(account->url) && strcmp(account->url, "http://"))
		terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", "URL", account->url);
	for (struct field *found_field = account->field_head; found_field; found_field = found_field->next) {
		pretty_field = pretty_field_value(found_field);
		terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ": %s\n", found_field->name, pretty_field);
		free(pretty_field);
	}
	if (strlen(account->note))
		terminal_printf(TERMINAL_FG_YELLOW "%s" TERMINAL_RESET ":\n%s\n", "Notes", account->note);
}

struct account *find_account_by_url(struct blob *blob, const char *url)
{
	if (!(starts_with(url, "http://") || starts_with(url, "https://"))) {
		die("URL must begin with http:// or https://.");
	}

	struct account *found = NULL;
	bool url_https = starts_with(url, "https");

	if (strcmp(url, "0")) {
		for (struct account *account = blob->account_head; account; account = account->next) {
			bool account_url_https = starts_with(account->url, "https");
			int url_offset = 0;
			int account_url_offset = 0;

			// Check whether differing with http/https
			if (url_https != account_url_https) {
				// Add to pointers so we compare starting at '://'
				url_offset = url_https ? 5 : 4;
				account_url_offset = account_url_https ? 5 : 4;
			}

			if (starts_with(url + url_offset, account->url + account_url_offset)) {
				found = account;
			}
		}
	}
	if (!found) {
		die("Could not find URL %s.", url);
	}
	return found;
}
