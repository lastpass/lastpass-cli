/*
 * key derivation routines
 *
 * Copyright (C) 2014-2018 LastPass.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

static inline void fail_invalid_iteration_count() {
	die("Action required: Your current iteration count does not meet the minimum number of %d iterations . Increase the iteration count on another client that supports iteration number setting.", MINIMUM_ITERATIONS);
}

void kdf_login_key(const char *username, const char *password, int iterations, char hex[KDF_HEX_LEN])
{
	unsigned char hash[KDF_HASH_LEN];
	size_t password_len;
	_cleanup_free_ char *user_lower = xstrlower(username);

	password_len = strlen(password);

	if (iterations < MINIMUM_ITERATIONS)
		fail_invalid_iteration_count();

	pbkdf2_hash(user_lower, strlen(user_lower), password, password_len, iterations, hash);
	pbkdf2_hash(password, password_len, (char *)hash, KDF_HASH_LEN, 1, hash);

	bytes_to_hex(hash, &hex, KDF_HASH_LEN);
	mlock(hex, KDF_HEX_LEN);
}

void kdf_decryption_key(const char *username, const char *password, int iterations, unsigned char hash[KDF_HASH_LEN])
{
	_cleanup_free_ char *user_lower = xstrlower(username);

	if (iterations < MINIMUM_ITERATIONS)
		fail_invalid_iteration_count();

	pbkdf2_hash(user_lower, strlen(user_lower), password, strlen(password), iterations, hash);
	mlock(hash, KDF_HASH_LEN);
}
