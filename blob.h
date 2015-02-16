#ifndef BLOB_H
#define BLOB_H

#include "kdf.h"
#include "session.h"
#include "list.h"
#include <stdbool.h>
#include <stddef.h>

struct share {
	int refcount;
	char *id;
	char *name;
	unsigned char key[KDF_HASH_LEN];
	bool readonly;

	char *chunk;
	size_t chunk_len;
};

struct field {
	char *type;
	char *name;
	char *value, *value_encrypted;
	bool checked;

	struct field *next;
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
	bool pwprotect;

	struct field *field_head;
	struct share *share;

	struct account *next;

	struct list_head match_list;
};

struct blob {
	unsigned long long version;
	bool local_version;
	/* TODO: extract other data eventually... */
	struct account *account_head;
};

enum blobsync { BLOB_SYNC_AUTO, BLOB_SYNC_YES, BLOB_SYNC_NO };

struct blob *blob_parse(const char *blob, size_t len, const unsigned char key[KDF_HASH_LEN], const struct private_key *private_key);
void blob_free(struct blob *blob);
size_t blob_write(const struct blob *blob, const unsigned char key[KDF_HASH_LEN], char **out);
struct blob *blob_load(enum blobsync sync, struct session *session, const unsigned char key[KDF_HASH_LEN]);
void blob_save(const struct blob *blob, const unsigned char key[KDF_HASH_LEN]);
void field_free(struct field *field);
void account_free(struct account *account);
void account_set_username(struct account *account, char *username, unsigned const char key[KDF_HASH_LEN]);
void account_set_password(struct account *account, char *password, unsigned const char key[KDF_HASH_LEN]);
void account_set_group(struct account *account, char *group, unsigned const char key[KDF_HASH_LEN]);
void account_set_name(struct account *account, char *name, unsigned const char key[KDF_HASH_LEN]);
void account_set_fullname(struct account *account, char *fullname, unsigned const char key[KDF_HASH_LEN]);
void account_set_note(struct account *account, char *note, unsigned const char key[KDF_HASH_LEN]);
void field_set_value(struct account *account, struct field *field, char *value, unsigned const char key[KDF_HASH_LEN]);
struct account *notes_expand(struct account *acc);
struct account *notes_collapse(struct account *acc);
void share_free(struct share *share);
void share_assign(struct share *share, struct share **ptr);

#endif
