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

#endif
