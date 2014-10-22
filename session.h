#ifndef SESSION_H
#define SESSION_H

#include "kdf.h"
#include <stdbool.h>

struct private_key {
	unsigned char *key;
	size_t len;
};
struct session {
	char *uid;
	char *sessionid;
	char *token;
	struct private_key private_key;
};

struct session *session_new();
void session_free(struct session *session);
bool session_is_valid(struct session *session);
struct session *sesssion_load(unsigned const char key[KDF_HASH_LEN]);
void session_save(struct session *session, unsigned const char key[KDF_HASH_LEN]);
void session_set_private_key(struct session *session, unsigned const char key[KDF_HASH_LEN], const char *key_hex);

#endif
