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

char *extract_regex_string(const char *s)
{
	int s_length = strlen(s);
	if(s && s_length > 2 && s[0] == '/' && s[s_length-1] == '/') {
		char *regex_string = (char*) malloc((s_length - 1) * sizeof(char));
		strncpy(regex_string, (const char *) &s[1], s_length - 1);
		regex_string[s_length-2] = '\0';

		return regex_string;
	}

	return NULL;
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

		char *regex_string;
		if (!found && (regex_string = extract_regex_string(name))) {
			regex_t regex;
			if(regcomp(&regex, regex_string, REG_ICASE))
				die("No account that matches '%s' and not a valid regex '%s'", name, regex_string);

			for (struct account *account = blob->account_head; account; account = account->next) {
				if (!regexec(&regex, account->name, 0, NULL, 0)) {
					if (found)
						die("Multiple matches found for regex %s: '%s' (ID: %s) / '%s' ID: %s'.", name, found->name, found->id, account->name, account->id);
					found = account;
				}
			}
			free(regex_string);
		}
	}
	return found;
}
