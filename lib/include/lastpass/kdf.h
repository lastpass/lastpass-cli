#ifndef KDF_H
#define KDF_H

#include <sys/types.h>
#include <openssl/sha.h>

#define KDF_HASH_LEN SHA256_DIGEST_LENGTH
#define KDF_HEX_LEN (KDF_HASH_LEN * 2 + 1)
void kdf_login_key(const char *username, const char *password, int iterations, char hex[KDF_HEX_LEN]);
void kdf_decryption_key(const char *username, const char *password, int iterations, unsigned char hash[KDF_HASH_LEN]);

#endif
