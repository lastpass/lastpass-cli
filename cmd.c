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
