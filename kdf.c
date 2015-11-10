/*
 * key derivation routines
 *
 * Copyright (C) 2014-2015 LastPass.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
 */
#include "kdf.h"
#include "util.h"
#include <string.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
static void pbkdf2_hash(const char *username, size_t username_len, const char *password, size_t password_len, int iterations, unsigned char hash[KDF_HASH_LEN])
{
	if (CCKeyDerivationPBKDF(kCCPBKDF2, password, password_len, (const uint8_t *)username, username_len, kCCPRFHmacAlgSHA256, iterations, hash, KDF_HASH_LEN) == kCCParamError)
		die("Failed to compute PBKDF2 for %s", username);
}
#else
#include "pbkdf2.h"

static void pbkdf2_hash(const char *username, size_t username_len, const char *password, size_t password_len, int iterations, unsigned char hash[KDF_HASH_LEN])
{
	if (!PKCS5_PBKDF2_HMAC(password, password_len, (const unsigned char *)username, username_len, iterations, EVP_sha256(), KDF_HASH_LEN, hash))
		die("Failed to compute PBKDF2 for %s", username);
}
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
		bytes_to_hex(hash, &hex, KDF_HASH_LEN);
		sha256_hash(hex, KDF_HEX_LEN - 1, password, password_len, hash);
	} else {
		pbkdf2_hash(user_lower, strlen(user_lower), password, password_len, iterations, hash);
		pbkdf2_hash(password, password_len, (char *)hash, KDF_HASH_LEN, 1, hash);
	}

	bytes_to_hex(hash, &hex, KDF_HASH_LEN);
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
		pbkdf2_hash(user_lower, strlen(user_lower), password, strlen(password), iterations, hash);
	mlock(hash, KDF_HASH_LEN);
}
