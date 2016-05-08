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

enum edit_choice
{
	EDIT_NONE,
	EDIT_USERNAME,
	EDIT_PASSWORD,
	EDIT_URL,
	EDIT_FIELD,
	EDIT_NAME,
	EDIT_NOTES,
	EDIT_ANY
};

void init_all(enum blobsync sync, unsigned char key[KDF_HASH_LEN], struct session **session, struct blob **blob);
enum blobsync parse_sync_string(const char *str);
struct account *find_unique_account(struct blob *blob, const char *name);
void find_matching_accounts(struct list_head *accounts, const char *name,
			    struct list_head *ret_list);
void find_matching_regex(struct list_head *accounts, const char *pattern,
			 int fields, struct list_head *ret_list);
void find_matching_substr(struct list_head *accounts, const char *pattern,
			  int fields, struct list_head *ret_list);
enum color_mode parse_color_mode_string(const char *colormode);
bool parse_bool_arg_string(const char *extra);
enum note_type parse_note_type_string(const char *extra);

int edit_account(struct session *session,
		 struct blob *blob,
		 enum blobsync sync,
		 struct account *editable,
		 enum edit_choice choice,
		 const char *field,
		 bool non_interactive,
		 unsigned char key[KDF_HASH_LEN]);

int edit_new_account(struct session *session,
		     struct blob *blob,
		     enum blobsync sync,
		     const char *name,
		     enum edit_choice choice,
		     const char *field,
		     bool non_interactive,
		     bool is_app,
		     enum note_type note_type,
		     unsigned char key[KDF_HASH_LEN]);

#define opt_color           "[--color=auto|never|always] "
#define opt_sync            "[--sync=auto|now|no] "
#define opt_force           "[--force, -f] "
#define opt_clip            "[--clip, -c] "
#define opt_non_interactive "[--non-interactive]"
#define opt_uid             "{UNIQUENAME|UNIQUEID} "
#define cmd_indent    "\n                  "

int cmd_login(int argc, char **argv);
#define cmd_login_usage "login     [--trust] [--plaintext-key " opt_force "]" \
                        cmd_indent opt_color " USERNAME"

int cmd_logout(int argc, char **argv);
#define cmd_logout_usage "logout    " opt_force opt_color

int cmd_passwd(int argc, char **argv);
#define cmd_passwd_usage "passwd"

int cmd_show(int argc, char **argv);

#define cmd_show_usage \
  "show      " opt_sync opt_clip "[--expand-multi, -x]" cmd_indent \
  "[--all|--username|--password|--url|--notes|--field=FIELD|--id|--name]" \
  cmd_indent "[--basic-regexp, -G|--fixed-strings, -F]" \
  cmd_indent opt_color opt_uid

int cmd_ls(int argc, char **argv);
#define cmd_ls_usage \
  "ls        " opt_sync "[--long, -l] " cmd_indent opt_color " [GROUP]"

int cmd_add(int argc, char **argv);
#define cmd_add_usage \
  "add       " opt_sync opt_non_interactive \
  cmd_indent opt_color cmd_indent \
  "{--username|--password|--url|--notes|--field=FIELD} NAME"

int cmd_edit(int argc, char **argv);
#define cmd_edit_usage \
  "edit      " opt_sync cmd_indent \
  opt_non_interactive opt_color  cmd_indent \
  "{--name|--username|--password|--url|--notes|--field=FIELD}" \
  cmd_indent "{NAME|UNIQUEID}"

int cmd_generate(int argc, char **argv);
#define cmd_generate_usage \
  "generate  " opt_sync opt_clip cmd_indent \
  "[--username=USERNAME] [--url=URL] [--no-symbols]" \
  cmd_indent "{NAME|UNIQUEID} LENGTH"

int cmd_duplicate(int argc, char **argv);
#define cmd_duplicate_usage \
  "duplicate " opt_sync opt_color cmd_indent opt_uid

int cmd_rm(int argc, char **argv);
#define cmd_rm_usage \
  "rm        " opt_sync opt_color cmd_indent opt_uid

int cmd_sync(int argc, char **argv);
#define cmd_sync_usage "sync      [--background, -b] " opt_color

int cmd_export(int argc, char **argv);
#define cmd_export_usage "export    " opt_sync opt_color

int cmd_share(int argc, char **argv);
#define cmd_share_usage "share subcommand sharename ..."

int cmd_mv(int argc, char **argv);
#define cmd_mv_usage "mv        " opt_color opt_uid "GROUP"

#endif /* #ifndef CMD_H */
