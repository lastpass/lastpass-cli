#ifndef CIPHER_H
#define CIPHER_H

#include "kdf.h"
#include "session.h"

char *cipher_rsa_decrypt(const char *ciphertext, size_t len, const struct private_key *private_key);
char *cipher_aes_decrypt(const char *ciphertext, size_t len, const unsigned char key[KDF_HASH_LEN]);
char *cipher_aes_decrypt_base64(const char *ciphertext, const unsigned char key[KDF_HASH_LEN]);
size_t cipher_aes_encrypt(const char *plaintext, const unsigned char key[KDF_HASH_LEN], char **ciphertext);
char *cipher_base64(const char *bytes, size_t len);

#endif
