#ifndef CMD_H
#define CMD_H

#include "blob.h"
#include "session.h"
#include "kdf.h"

void init_all(enum blobsync sync, unsigned char key[KDF_HASH_LEN], struct session **session, struct blob **blob);
enum blobsync parse_sync_string(const char *str);
struct account *find_unique_account(struct blob *blob, const char *name);
char *pretty_field_value(struct field *field);
void account_print_all(struct account *account);
struct account *find_account_by_url(struct blob *blob, const char *url);

int cmd_login(int argc, char **argv);
#define cmd_login_usage "login [--trust] [--plaintext-key [--force, -f]] USERNAME"

int cmd_logout(int argc, char **argv);
#define cmd_logout_usage "logout [--force, -f]"

int cmd_show(int argc, char **argv);
#define cmd_show_usage "show [--sync=auto|now|no] [--clip, -c] [--all|--username|--password|--url|--notes|--field=FIELD|--id|--name] {UNIQUENAME|UNIQUEID}"

int cmd_ls(int argc, char **argv);
#define cmd_ls_usage "ls [--sync=auto|now|no] [GROUP]"

int cmd_find(int argc, char **argv);
#define cmd_find_usage "find [--sync=auto|now|no] URL"

int cmd_edit(int argc, char **argv);
#define cmd_edit_usage "edit [--sync=auto|now|no] [--non-interactive] {--name|--username|--password|--url|--notes|--field=FIELD} {NAME|UNIQUEID}"

int cmd_generate(int argc, char **argv);
#define cmd_generate_usage "generate [--sync=auto|now|no] [--clip, -c] [--username=USERNAME] [--url=URL] [--no-symbols] {NAME|UNIQUEID} LENGTH"

int cmd_duplicate(int argc, char **argv);
#define cmd_duplicate_usage "duplicate [--sync=auto|now|no] {UNIQUENAME|UNIQUEID}"

int cmd_rm(int argc, char **argv);
#define cmd_rm_usage "rm [--sync=auto|now|no] {UNIQUENAME|UNIQUEID}"

int cmd_sync(int argc, char **argv);
#define cmd_sync_usage "sync [--background, -b]"

#endif
