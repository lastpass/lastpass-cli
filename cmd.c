/*
 * Copyright (c) 2014 LastPass. All Rights Reserved.
 *
 *
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

struct account *find_unique_account(struct blob *blob, const char *name)
{
	struct account *found = NULL;
	char *fullname;
	int ret;

	if (strcmp(name, "0")) {
		for (struct account *account = blob->account_head; account; account = account->next) {
			if (!strcasecmp(account->id, name)) {
				found = account;
				break;
			}
		}
	}
	if (!found) {
		for (struct account *account = blob->account_head; account; account = account->next) {
			if (account->share)
				xasprintf(&fullname, "%s/%s", account->share->name, account->fullname);
			else
				fullname = xstrdup(account->fullname);
			ret = strcmp(fullname, name);
			free(fullname);
			if (!ret) {
				if (found)
					die("Multiple matches found for '%s'. You must specify an ID instead of a name.", name);
				found = account;
			}
		}
		if (!found) {
			for (struct account *account = blob->account_head; account; account = account->next) {
				if (!strcmp(account->name, name)) {
					if (found)
						die("Multiple matches found for '%s'. You must specify an ID instead of a name.", name);
					found = account;
				}
			}
		}
	}
	return found;
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
