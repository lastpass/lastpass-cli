#ifndef BLOB_H
#define BLOB_H

#include "kdf.h"
#include "session.h"
#include "list.h"
#include "notes.h"
#include <stdbool.h>
#include <stddef.h>

struct share_user {
	char *uid;
	char *username;
	char *realname;
	char *cgid;
	bool read_only;
	bool is_group;		/* if set uid, username store gid, groupname */
	bool hide_passwords;
	bool admin;
	bool outside_enterprise;
	bool accepted;
	struct public_key sharing_key;
	struct list_head list;
};

struct share_limit_aid {
	char *aid;
	struct list_head list;
};

struct share_limit {
	bool whitelist;
	struct list_head aid_list;
};

struct share {
	char *id;
	char *name;
	unsigned char key[KDF_HASH_LEN];
	bool readonly;

	char *chunk;
	size_t chunk_len;

	struct list_head list;
};

struct field {
	char *type;
	char *name;
	char *value, *value_encrypted;
	bool checked;

	struct list_head list;
};

struct account {
	char *id;
	char *name, *name_encrypted;
	char *group, *group_encrypted;
	char *fullname;
	char *url;
	char *username, *username_encrypted;
	char *password, *password_encrypted;
	char *note, *note_encrypted;
	char *last_touch, *last_modified_gmt;
	bool pwprotect;
	bool fav;
	bool is_app;
	char *attachkey, *attachkey_encrypted;
	bool attachpresent;
	size_t attach_len;
	char *attach_bytes;

	struct list_head field_head;
	struct share *share;

	struct list_head attach_head;

	struct list_head list;
	struct list_head match_list;
};

struct app {
	struct account account;

	char *appname;
	char *extra, *extra_encrypted;
	char *wintitle;
	char *wininfo;
	char *exeversion;
	char *warnversion;
	char *exehash;
};

struct attach {
	char *id;
	char *parent;
	char *mimetype;
	char *storagekey;
	char *size;
	char *filename;

	struct list_head list;
};

/* resizable string buffer */
struct buffer {
	size_t len;
	size_t max;
	char *bytes;
};

struct blob {
	unsigned long long version;
	bool local_version;
	/* TODO: extract other data eventually... */

	struct list_head account_head;
	struct list_head share_head;
};

/* state used during master password change */
struct pwchange_info {
	char *reencrypt_id;
	char *token;
	char *privkey_encrypted;
	char *new_privkey_encrypted;
	char *new_privkey_hash;
	char *new_key_hash;
	struct list_head fields;
	struct list_head su_keys;
};

/* replacement items for password change blob updates */
struct pwchange_field {
	char *old_ctext;
	char *new_ctext;
	bool optional;
	struct list_head list;
};

/* Super-user keys used for enterprise password recovery. */
struct pwchange_su_key {
	char *uid;			/* uid for super user */
	struct public_key sharing_key;	/* pubkey for this user */
	char *new_enc_key;		/* user AES key, enc w/ SU's RSA key */
	struct list_head list;
};

enum blobsync { BLOB_SYNC_AUTO, BLOB_SYNC_YES, BLOB_SYNC_NO };

struct blob *blob_parse(const unsigned char *blob, size_t len, const unsigned char key[KDF_HASH_LEN], const struct private_key *private_key);
void blob_free(struct blob *blob);
size_t blob_write(const struct blob *blob, const unsigned char key[KDF_HASH_LEN], char **out);
struct blob *blob_load(enum blobsync sync, struct session *session, const unsigned char key[KDF_HASH_LEN]);
void blob_save(const struct blob *blob, const unsigned char key[KDF_HASH_LEN]);
void field_free(struct field *field);
struct app *account_to_app(const struct account *account);
struct app *new_app();
struct account *new_account();
void account_free(struct account *account);
void account_set_username(struct account *account, char *username, unsigned const char key[KDF_HASH_LEN]);
void account_set_password(struct account *account, char *password, unsigned const char key[KDF_HASH_LEN]);
void account_set_group(struct account *account, char *group, unsigned const char key[KDF_HASH_LEN]);
void account_set_name(struct account *account, char *name, unsigned const char key[KDF_HASH_LEN]);
void account_set_fullname(struct account *account, char *fullname, unsigned const char key[KDF_HASH_LEN]);
void account_set_url(struct account *account, char *url, unsigned const char key[KDF_HASH_LEN]);
void account_set_note(struct account *account, char *note, unsigned const char key[KDF_HASH_LEN]);
void account_set_appname(struct account *account, char *appname, unsigned const char key[KDF_HASH_LEN]);
void account_assign_share(struct blob *blob, struct account *account, unsigned const char key[KDF_HASH_LEN]);
void account_reencrypt(struct account *account, const unsigned char key[KDF_HASH_LEN]);
bool account_is_group(struct account *account);
void field_set_value(struct account *account, struct field *field, char *value, unsigned const char key[KDF_HASH_LEN]);
struct account *notes_expand(struct account *acc);
struct account *notes_collapse(struct account *acc);
void share_free(struct share *share);
struct share *find_unique_share(struct blob *blob, const char *name);
void buffer_init(struct buffer *buf);
void buffer_append(struct buffer *buffer, void *bytes, size_t len);
void buffer_append_char(struct buffer *buf, char c);
void buffer_append_str(struct buffer *buf, char *str);

#endif
