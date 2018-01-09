/*
 * command for importing vault entries from CSV file into the vault
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
#include "util.h"
#include "config.h"
#include "terminal.h"
#include "kdf.h"
#include "blob.h"
#include "endpoints.h"
#include "agent.h"
#include "list.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <search.h>

struct csv_record {
	struct list_head field_head;
	struct list_head list;
};

struct csv_field {
	char *value;
	struct list_head list;
};

enum csv_token {
	CSV_NONE,
	CSV_FIELD,
	CSV_NL,
	CSV_EOF
};

static enum csv_token csv_next_token(FILE *fp, char **retp)
{
	int ch, nextch;
	bool readch = false;
	bool in_quote = false;
	bool done = false;
	bool eol = false;
	char *rptr;

	struct buffer result = {
		.len = 0,
		.max = 80,
		.bytes = NULL,
	};
	result.bytes = xcalloc(result.max, 1);

	*retp = NULL;
	while (!done) {
		ch = fgetc(fp);
		if (ch == EOF)
			break;

		readch = true;
		switch(ch)
		{
		case '\n':
		case ',':
			/* non-quoted newline / comma terminate field */
			if (!in_quote) {
				done = true;
				eol = (ch == '\n');
				break;
			}

			/* otherwise append */
			buffer_append_char(&result, ch);
			break;

		case '"':
			/*
			 * quote immediately after comma starts a
			 * double-quoted field
			 */
			if (result.len == 0 && !in_quote) {
				in_quote = true;
				continue;
			}

			if (in_quote) {
				/*
				 * inside a dqfield, two double quotes adds a
				 * quote, print one
				 */
				nextch = fgetc(fp);
				if (nextch == '"') {
					buffer_append_char(&result, '"');
					continue;
				}

				/* otherwise terminate the quote */
				in_quote = false;
				ungetc(nextch, fp);
				continue;
			}
			/* quote not after a comma, treat as unescaped */
			buffer_append_char(&result, ch);
			break;
		default:
			buffer_append_char(&result, ch);
		}
	}

	if (!readch)
		return CSV_EOF;

	rptr = result.bytes;
	/* trim cr/nl, but not spaces (they may be significant) */
	while (rptr[strlen(rptr)-1] == '\r' ||
	       rptr[strlen(rptr)-1] == '\n') {
		rptr[strlen(rptr)-1] = '\0';
	}
	*retp = rptr;

	if (eol)
		return CSV_NL;

	return CSV_FIELD;
}

static struct csv_record *csv_record_new()
{
	struct csv_record *r;

	r = new0(struct csv_record, 1);
	INIT_LIST_HEAD(&r->field_head);
	return r;
}

/*
 * Return a list of csv_record items from parsing a CSV file.
 */
static void csv_parse(FILE *fp, struct list_head *list)
{
	char *p;
	enum csv_token token;
	struct csv_record *record;

	record = csv_record_new();
	while ((token = csv_next_token(fp, &p))) {
		if (p) {
			struct csv_field *field = new0(struct csv_field, 1);
			field->value = p;
			list_add_tail(&field->list, &record->field_head);
		}
		if (token == CSV_NL || token == CSV_EOF) {
			if (!list_empty(&record->field_head)) {
				list_add_tail(&record->list, list);
				record = csv_record_new();
			}
		}
		if (token == CSV_EOF)
			break;
	}
	free(record);
}

static struct account *new_import_account(unsigned char key[KDF_HASH_LEN])
{
	struct account *account = new_account();

	account_set_url(account, xstrdup(""), key);
	account_set_username(account, xstrdup(""), key);
	account_set_password(account, xstrdup(""), key);
	account_set_note(account, xstrdup(""), key);
	account_set_name(account, xstrdup(""), key);
	account_set_group(account, xstrdup(""), key);

	return account;
}

static int csv_parse_accounts(FILE *fp, struct list_head *account_list,
			      unsigned char key[KDF_HASH_LEN])
{
	struct list_head items;
	struct csv_record *record, *tmp_record, *first;
	struct csv_field *field, *tmp_field;
	int i = 0;
	int num_accounts = 0;

	int url_index = -1,
	    username_index = -1,
	    password_index = -1,
	    extra_index = -1,
	    name_index = -1,
	    grouping_index = -1,
	    fav_index = -1;

	INIT_LIST_HEAD(&items);
	csv_parse(fp, &items);

	if (list_empty(&items))
		return 0;

#define set_field_index(x) \
	do { \
		if (!strcmp(field->value, #x)) { \
			x ## _index = i; \
		} \
	} while (0)

#define set_field(x, fieldname) \
	do { \
		if (i == x ## _index) { \
			account_set_ ## fieldname (account, field->value, key); \
			set = true; \
		} \
	} while (0)

	/*
	 * first line should tell us the field matrix; if
	 * it doesn't reveal anything useful then we won't
	 * import anything
	 */
	record = list_first_entry(&items, struct csv_record, list);
	list_for_each_entry(field, &record->field_head, list) {
		set_field_index(url);
		set_field_index(username);
		set_field_index(password);
		set_field_index(extra);
		set_field_index(name);
		set_field_index(grouping);
		set_field_index(fav);
		i++;
	}

	if (url_index == -1 && username_index == -1 &&
	    password_index == -1 && extra_index == -1 &&
	    name_index == -1 && grouping_index == -1 &&
	    fav_index == -1)
		return 0;

	first = record;
	list_for_each_entry(record, &items, list) {
		struct account *account;
		if (record == first)
			continue;

		account = new_import_account(key);
		i = 0;
		list_for_each_entry(field, &record->field_head, list) {
			bool set = false;
			set_field(url, url);
			set_field(username, username);
			set_field(password, password);
			set_field(name, name);
			set_field(grouping, group);
			set_field(extra, note);
			if (i == fav_index) {
				account->fav = field->value[0] == '1';
				set = true;
			}

			/* free unknown field */
			if (!set)
				free(field->value);
			i++;
		}
		num_accounts++;
		list_add_tail(&account->list, account_list);
	}

	list_for_each_entry_safe(record, tmp_record, &items, list) {
		list_for_each_entry_safe(field, tmp_field,
					 &record->field_head, list) {
			free(field);
		}
		free(record);
	}
	return num_accounts;
}

/* dedupe based on password / url / name / username sets */
int csv_dedupe_compare(const void *k1, const void *k2)
{
	const struct account *a1 = k1, *a2 = k2;
	int r;

	if ((r = strcmp(a1->password, a2->password)))
		return r;
	if ((r = strcmp(a1->username, a2->username)))
		return r;
	if ((r = strcmp(a1->url, a2->url)))
		return r;
	return strcmp(a1->name, a2->name);
}

void csv_dedupe_accounts(struct list_head *blob_accounts,
			 struct list_head *new_accounts)
{
	struct account *account, *tmp;
	void *search_tree = NULL;

	list_for_each_entry(account, blob_accounts, list) {
		tsearch(account, &search_tree, csv_dedupe_compare);
	}

	list_for_each_entry_safe(account, tmp, new_accounts, list) {
		if (tfind(account, &search_tree, csv_dedupe_compare)) {
			list_del(&account->list);
			account_free(account);
		}
	}
}

int cmd_import(int argc, char **argv)
{
	static struct option long_options[] = {
		{"sync", required_argument, NULL, 'S'},
		{"keep-dupes", no_argument, NULL, 'k'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	enum blobsync sync = BLOB_SYNC_AUTO;
	unsigned char key[KDF_HASH_LEN];
	_cleanup_fclose_ FILE *fp;
	struct session *session = NULL;
	struct blob *blob = NULL;
	struct list_head accounts;
	struct account *account;
	int count, new_count;
	bool keep_dupes = false;
	int ret;

	while ((option = getopt_long(argc, argv, "", long_options, &option_index)) != -1) {
		switch (option) {
		case 'S':
			sync = parse_sync_string(optarg);
			break;
		case 'k':
			keep_dupes = true;
			break;
		case '?':
		default:
			die_usage(cmd_import_usage);
		}
	}

	if (argc - optind < 1) {
		fp = stdin;
	} else {
		char *filename = argv[optind];
		fp = fopen(filename, "rb");
		if (!fp)
			die("Unable to open %s", filename);
	}

	init_all(sync, key, &session, &blob);

	INIT_LIST_HEAD(&accounts);
	count = csv_parse_accounts(fp, &accounts, key);

	printf("Parsed %d accounts\n", count);

	new_count = 0;
	if (!keep_dupes)
		csv_dedupe_accounts(&blob->account_head, &accounts);

	list_for_each_entry(account, &accounts, list) {
		new_count++;
	};

	if (count - new_count)
		printf("Removed %d duplicate accounts\n", count - new_count);

	ret = lastpass_upload(session, &accounts);
	if (ret)
		die("Import failed (%d)\n", ret);

	session_free(session);
	blob_free(blob);
	return 0;
}
