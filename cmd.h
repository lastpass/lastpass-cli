#ifndef CMD_H
#define CMD_H

#include "blob.h"
#include "session.h"
#include "terminal.h"
#include "kdf.h"

enum search_type
{
	SEARCH_EXACT_MATCH,
	SEARCH_BASIC_REGEX,
	SEARCH_FIXED_SUBSTRING,
};

#define BIT(x) (1ull << (x))

enum account_field
{
	ACCOUNT_ID = BIT(0),
	ACCOUNT_NAME = BIT(1),
	ACCOUNT_FULLNAME = BIT(2),
	ACCOUNT_URL = BIT(3),
	ACCOUNT_USERNAME = BIT(4),
};
void init_all(enum blobsync sync, unsigned char key[KDF_HASH_LEN], struct session **session, struct blob **blob);
enum blobsync parse_sync_string(const char *str);
struct account *find_unique_account(struct blob *blob, const char *name);
void find_matching_accounts(struct blob *blob, const char *name,
			    struct list_head *ret_list);
void find_matching_regex(struct blob *blob, const char *pattern,
			 int fields, struct list_head *ret_list);
void find_matching_substr(struct blob *blob, const char *pattern,
			  int fields, struct list_head *ret_list);
enum color_mode parse_color_mode_string(const char *colormode);
bool parse_bool_arg_string(const char *extra);

#define color_usage "[--color=auto|never|always]"

int cmd_login(int argc, char **argv);
#define cmd_login_usage "login [--trust] [--plaintext-key [--force, -f]] " color_usage " USERNAME"

int cmd_logout(int argc, char **argv);
#define cmd_logout_usage "logout [--force, -f] " color_usage

int cmd_show(int argc, char **argv);
#define cmd_show_usage "show [--sync=auto|now|no] [--clip, -c] [--all|--username|--password|--url|--notes|--field=FIELD|--id|--name] [--basic-regexp, -G|--fixed-strings, -F] " color_usage " {UNIQUENAME|UNIQUEID}"

int cmd_ls(int argc, char **argv);
#define cmd_ls_usage "ls [--sync=auto|now|no] [--long, -l] " color_usage " [GROUP]"

int cmd_edit(int argc, char **argv);
#define cmd_edit_usage "edit [--sync=auto|now|no] [--non-interactive] " color_usage " {--name|--username|--password|--url|--notes|--field=FIELD} {NAME|UNIQUEID}"

int cmd_generate(int argc, char **argv);
#define cmd_generate_usage "generate [--sync=auto|now|no] [--clip, -c] [--username=USERNAME] [--url=URL] [--no-symbols] {NAME|UNIQUEID} LENGTH"

int cmd_duplicate(int argc, char **argv);
#define cmd_duplicate_usage "duplicate [--sync=auto|now|no] " color_usage " {UNIQUENAME|UNIQUEID}"

int cmd_rm(int argc, char **argv);
#define cmd_rm_usage "rm [--sync=auto|now|no] " color_usage " {UNIQUENAME|UNIQUEID}"

int cmd_sync(int argc, char **argv);
#define cmd_sync_usage "sync [--background, -b] " color_usage

int cmd_export(int argc, char **argv);
#define cmd_export_usage "export [--sync=auto|now|no] " color_usage

int cmd_share(int argc, char **argv);
#define cmd_share_usage "share " color_usage " subcommand sharename..."
#endif
