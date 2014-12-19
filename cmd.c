/*
 * Copyright (c) 2014 LastPass.
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
#include <pcre.h>

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
 * Search blob for any and all accounts matching a given name.
 * Matching accounts are appended to ret_list which should be initialized
 * by the caller.
 *
 * In the case of an id match, we return only the matching id entry.
 */
void find_matching_accounts(struct blob *blob, const char *name,
			    struct list_head *ret_list)
{
	int ret;
	char *fullname;

	for (struct account *account = blob->account_head; account; account = account->next) {
		/* id match */
		if (strcmp(name, "0") && !strcasecmp(account->id, name)) {
			list_add_tail(&account->match_list, ret_list);
			/* if id match, stop processing */
			break;
		}

		/* full name match */
		if (account->share)
			xasprintf(&fullname, "%s/%s", account->share->name, account->fullname);
		else
			fullname = xstrdup(account->fullname);

		ret = strcmp(fullname, name);
		free(fullname);
		if (!ret) {
			list_add_tail(&account->match_list, ret_list);
			continue;
		}

		/* name match */
		if (!strcmp(account->name, name)) {
			list_add_tail(&account->match_list, ret_list);
			continue;
		}
	}
}


/*
 * Same as find_matching_accounts but with regular expression search and without "id" matching
 */
void find_matching_accounts_regex(struct blob *blob, const char *name,
			    struct list_head *ret_list)
{
	int ret;
	char *fullname;

	//---------------------
	pcre *re;
        pcre_extra *reExtra;
	const char *error;
	int erroffset;

	// Compile regex
	re = pcre_compile(
	  name,		        /* the pattern */
	  PCRE_CASELESS,        /* default options */
	  &error,               /* for error message */
	  &erroffset,           /* for error offset */
	  NULL);                /* use default character tables */

	// Catch compile error
	if (re == NULL)
	{
	  printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
	  return;
	}

	/* optimize regex */
	reExtra = pcre_study(re, 0, &error);


	for (struct account *account = blob->account_head; account; account = account->next) {

		/* full name match */
		if (account->share)
			xasprintf(&fullname, "%s/%s", account->share->name, account->fullname);
		else
			fullname = xstrdup(account->fullname);

		/* regex match fullname */
		ret = pcre_exec(
		      re,                 /* the compiled pattern */
		      reExtra,            /* extra */
		      fullname,           /* subject */
		      strlen(fullname),   /* length */
		      0,       	          /* start offset */
		      0,                  /* options */
		      NULL,
		      0
		     );

		if (ret>-1) {
			list_add_tail(&account->match_list, ret_list);
			free(fullname);
			continue;
		}

		if (account->name != NULL && fullname != account->name) {

                    /* regex match name */
                    ret = pcre_exec(
                          re,                 /* the compiled pattern */
                          reExtra,            /* extra */
                          account->name,      /* subject */
                          strlen(account->name),   /* length */
                          0,       	          /* start offset */
                          0,                  /* options */
                          NULL,
                          0
                         );

                    /* name match */
                    if (ret>-1) {
                            list_add_tail(&account->match_list, ret_list);
                    }
		}
	        free(fullname);


	}

	pcre_free(re);
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
