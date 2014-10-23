#ifndef AGENT_H
#define AGENT_H

#include "kdf.h"
#include <stdbool.h>

bool agent_get_decryption_key(unsigned char key[KDF_HASH_LEN]);
void agent_save(const char *username, int iterations, unsigned const char key[KDF_HASH_LEN]);
void agent_kill(void);
bool agent_load_key(unsigned char key[KDF_HASH_LEN]);

#endif
