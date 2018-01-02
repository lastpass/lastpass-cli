/*
 * general utility functions used by multiple commands
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
#include "agent.h"
#include "blob.h"
#include "session.h"
#include "util.h"
#include "process.h"
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

bool parse_bool_arg_string(const char *extra)
{
	return !extra || strcmp(extra, "true") == 0;
}

enum note_type parse_note_type_string(const char *extra)
{
	enum note_type result;

	result = notes_get_type_by_shortname(extra);
	if (result == NOTE_TYPE_NONE) {
		_cleanup_free_ char *params = NULL;
		_cleanup_free_ char *usage = NULL;

		params = note_type_usage();
		xasprintf(&usage, "... %s", params);
		die_usage(usage);
	}

	return result;
}

void init_all(enum blobsync sync, unsigned char key[KDF_HASH_LEN], struct session **session, struct blob **blob)
{
	if (!agent_get_decryption_key(key))
		die("Could not find decryption key. Perhaps you need to login with `%s login`.", ARGV[0]);

	*session = session_load(key);
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

/*
 * Search accounts with a given comparator.
 *
 * Any matched account is removed from the accounts list, and added to
 * ret_list.
 *
 * Note, the account list is iterated through match_list, so the caller
 * must first create a list of possible matches (from blob->account_head).
 * This is done instead of searching blob->account_head directly to enable
 * multiple searches of the potential match set.
 */
static void search_accounts(struct list_head *accounts,
			    const void *needle,
			    int (*cmp)(const char *haystack, const char *needle),
			    int fields,
			    struct list_head *ret_list)
{
	struct account *account, *tmp;
	list_for_each_entry_safe(account, tmp, accounts, match_list) {
		if (((fields & ACCOUNT_ID) && cmp(account->id, needle) == 0) ||
		    ((fields & ACCOUNT_NAME) && cmp(account->name, needle) == 0) ||
		    ((fields & ACCOUNT_FULLNAME) && cmp(account->fullname, needle) == 0) ||
		    ((fields & ACCOUNT_URL) && cmp(account->url, needle) == 0) ||
		    ((fields & ACCOUNT_USERNAME) && cmp(account->username, needle) == 0)) {
			list_del(&account->match_list);
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
void find_matching_regex(struct list_head *accounts, const char *pattern,
			 int fields, struct list_head *ret_list)
{
	regex_t regex;

	if (regcomp(&regex, pattern, REG_ICASE))
		die("Invalid regex '%s'", pattern);
	search_accounts(accounts, &regex, cmp_regex, fields, ret_list);
	regfree(&regex);
}

/*
 * Search accounts on name, username, and url fields, adding all matches
 * into ret_list.
 *
 * @pattern - a basic regular expression
 * @fields - which fields to search on
 */
void find_matching_substr(struct list_head *accounts, const char *pattern,
			  int fields, struct list_head *ret_list)
{
	search_accounts(accounts, pattern, cmp_substr, fields, ret_list);
}

/*
 * Search list of accounts for any and all accounts matching a given name.
 * Matching accounts are appended to ret_list which should be initialized
 * by the caller.
 *
 * In the case of an id match, we return only the matching id entry.
 */
void find_matching_accounts(struct list_head *accounts, const char *name,
			    struct list_head *ret_list)
{
	/* look for exact id match */
	struct account *account;
	list_for_each_entry(account, accounts, match_list) {
		if (strcmp(name, "0") && !strcasecmp(account->id, name)) {
			list_del(&account->match_list);
			list_add_tail(&account->match_list, ret_list);
			/* if id match, stop processing */
			return;
		}
	}

	/* search for fullname or name match */
	search_accounts(accounts, name, strcmp,
			ACCOUNT_NAME | ACCOUNT_FULLNAME,
			ret_list);
}

struct account *find_unique_account(struct blob *blob, const char *name)
{
	struct list_head matches;
	struct list_head potential_set;
	struct account *account, *last_account;

	INIT_LIST_HEAD(&matches);
	INIT_LIST_HEAD(&potential_set);

	list_for_each_entry(account, &blob->account_head, list)
		list_add(&account->match_list, &potential_set);

	find_matching_accounts(&potential_set, name, &matches);

	if (list_empty(&matches))
		return NULL;

	account = list_first_entry(&matches, struct account, match_list);
	last_account = list_last_entry(&matches, struct account, match_list);

	if (account != last_account)
		die("Multiple matches found for '%s'. You must specify an ID instead of a name.", name);

	return account;
}
