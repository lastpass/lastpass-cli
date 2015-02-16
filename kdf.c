/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "kdf.h"
#include "util.h"
#include <string.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000000L || !(defined(__APPLE__) && defined(__MACH__))
static void pdkdf2_hash(const char *username, size_t username_len, const char *password, size_t password_len, int iterations, unsigned char hash[KDF_HASH_LEN])
{
	if (!PKCS5_PBKDF2_HMAC(password, password_len, (const unsigned char *)username, username_len, iterations, EVP_sha256(), KDF_HASH_LEN, hash))
		die("Failed to compute PBKDF2 for %s", username);
}
#elif defined(__APPLE__) && defined(__MACH__)
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
static void pdkdf2_hash(const char *username, size_t username_len, const char *password, size_t password_len, int iterations, unsigned char hash[KDF_HASH_LEN])
{
	if (CCKeyDerivationPBKDF(kCCPBKDF2, password, password_len, (const uint8_t *)username, username_len, kCCPRFHmacAlgSHA256, iterations, hash, KDF_HASH_LEN) == kCCParamError)
		die("Failed to compute PBKDF2 for %s", username);
}
#else
#error Failed to build a suitable PBKDF2-HMAC
#endif

static void sha256_hash(const char *username, size_t username_len, const char *password, size_t password_len, unsigned char hash[KDF_HASH_LEN])
{
	SHA256_CTX sha256;

	if (!SHA256_Init(&sha256))
		goto die;
	if (!SHA256_Update(&sha256, username, username_len))
		goto die;
	if (!SHA256_Update(&sha256, password, password_len))
		goto die;
	if (!SHA256_Final(hash, &sha256))
		goto die;
	return;

die:
	die("Failed to compute SHA256 for %s", username);
}

void kdf_login_key(const char *username, const char *password, int iterations, char hex[KDF_HEX_LEN])
{
	unsigned char hash[KDF_HASH_LEN];
	size_t password_len;
	_cleanup_free_ char *user_lower = xstrlower(username);

	password_len = strlen(password);

	if (iterations < 1)
		iterations = 1;

	if (iterations == 1) {
		sha256_hash(user_lower, strlen(user_lower), password, password_len, hash);
		bytes_to_hex((char *)hash, &hex, KDF_HASH_LEN);
		sha256_hash(hex, KDF_HEX_LEN - 1, password, password_len, hash);
	} else {
		pdkdf2_hash(user_lower, strlen(user_lower), password, password_len, iterations, hash);
		pdkdf2_hash(password, password_len, (char *)hash, KDF_HASH_LEN, 1, hash);
	}

	bytes_to_hex((char *)hash, &hex, KDF_HASH_LEN);
	mlock(hex, KDF_HEX_LEN);
}

void kdf_decryption_key(const char *username, const char *password, int iterations, unsigned char hash[KDF_HASH_LEN])
{
	_cleanup_free_ char *user_lower = xstrlower(username);

	if (iterations < 1)
		iterations = 1;

	if (iterations == 1)
		sha256_hash(user_lower, strlen(user_lower), password, strlen(password), hash);
	else
		pdkdf2_hash(user_lower, strlen(user_lower), password, strlen(password), iterations, hash);
	mlock(hash, KDF_HASH_LEN);
}
