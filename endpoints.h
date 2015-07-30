#ifndef ENDPOINTS_H
#define ENDPOINTS_H

#include "session.h"
#include "blob.h"
#include "kdf.h"
#include <stddef.h>

unsigned int lastpass_iterations(const char *username);
struct session *lastpass_login(const char *username, const char hash[KDF_HEX_LEN], const unsigned char key[KDF_HASH_LEN], int iterations, char **error_message, bool trust);
void lastpass_logout(const struct session *session);
struct blob *lastpass_get_blob(const struct session *session, const unsigned char key[KDF_HASH_LEN]);
unsigned long long lastpass_get_blob_version(struct session *session, unsigned const char key[KDF_HASH_LEN]);
void lastpass_remove_account(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const struct account *account, struct blob *blob);
void lastpass_update_account(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const struct account *account, struct blob *blob);
void lastpass_log_access(enum blobsync sync, const struct session *session, unsigned const char key[KDF_HASH_LEN], const struct account *account);

int lastpass_share_getinfo(const struct session *session, const char *shareid, struct list_head *users);
int lastpass_share_user_add(const struct session *session, struct share *share, struct share_user *user);
int lastpass_share_user_del(const struct session *session, const char *shareid, struct share_user *user);
int lastpass_share_user_mod(const struct session *session, struct share *share, struct share_user *user);
int lastpass_share_create(const struct session *session, const char *sharename);
int lastpass_share_delete(const struct session *session, struct share *share);
#endif
