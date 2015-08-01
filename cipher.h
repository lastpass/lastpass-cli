#ifndef CIPHER_H
#define CIPHER_H

#include "kdf.h"
#include "session.h"

char *cipher_rsa_decrypt(const unsigned char *ciphertext, size_t len, const struct private_key *private_key);
int cipher_rsa_encrypt(const char *plaintext,
		       const struct public_key *public_key,
		       unsigned char *out_crypttext, size_t *out_len);
char *cipher_aes_decrypt(const unsigned char *ciphertext, size_t len, const unsigned char key[KDF_HASH_LEN]);
char *cipher_aes_decrypt_base64(const char *ciphertext, const unsigned char key[KDF_HASH_LEN]);
size_t cipher_aes_encrypt(const char *plaintext, const unsigned char key[KDF_HASH_LEN], char **ciphertext);
char *cipher_base64(const char *bytes, size_t len);
char *encrypt_and_base64(const char *str, unsigned const char key[KDF_HASH_LEN]);

#endif
