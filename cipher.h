#ifndef CIPHER_H
#define CIPHER_H

#include <stdbool.h>
#include "kdf.h"
#include "session.h"

#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16
#define AES_GCM_MIN_LEN (1 + AES_GCM_IV_LEN + AES_GCM_TAG_LEN)

#define CIPHER_MARKER_CBC '!'
#define CIPHER_MARKER_GCM '#'

enum cipher_aes_mode {
	CIPHER_AES_ECB,
	CIPHER_AES_CBC,
	CIPHER_AES_GCM,
};

char *cipher_rsa_decrypt(const unsigned char *ciphertext, size_t len, const struct private_key *private_key);
int cipher_rsa_encrypt_bytes(const unsigned char *plaintext,
			     size_t in_len,
			     const struct public_key *public_key,
			     unsigned char *out_crypttext, size_t *out_len);
int cipher_rsa_encrypt(const char *plaintext,
		       const struct public_key *public_key,
		       unsigned char *out_crypttext, size_t *out_len);
bool cipher_is_marker(unsigned char byte);
char *cipher_aes_decrypt(const unsigned char *ciphertext, size_t len, const unsigned char key[KDF_HASH_LEN]);
char *cipher_aes_decrypt_mode(const unsigned char *ciphertext, size_t len, const unsigned char key[KDF_HASH_LEN], enum cipher_aes_mode *mode);
char *cipher_aes_decrypt_base64(const char *ciphertext, const unsigned char key[KDF_HASH_LEN]);
size_t cipher_aes_encrypt(const char *plaintext, const unsigned char key[KDF_HASH_LEN], unsigned char **ciphertext);
char *cipher_base64(const unsigned char *bytes, size_t len);
char *cipher_base64_mode(const unsigned char *bytes, size_t len, enum cipher_aes_mode mode);
size_t cipher_unbase64(const char *ciphertext, unsigned char **b64data);
size_t unbase64(const char *ptext, unsigned char **b64data);
char *encrypt_and_base64(const char *str, unsigned const char key[KDF_HASH_LEN]);
bool cipher_decrypt_private_key(const char *key_hex, unsigned const char key[KDF_HASH_LEN], struct private_key *out_key);
char *cipher_encrypt_private_key(struct private_key *private_key,
				 unsigned const char key[KDF_HASH_LEN]);
char *cipher_sha256_hex(unsigned char *bytes, size_t len);
char *cipher_sha256_b64(unsigned char *bytes, size_t len);
char *cipher_multi_sha256_hex(int num_args, ...);
#endif
