/*
 * encryption and decryption routines
 *
 * Copyright (C) 2014-2024 LastPass.
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
#include "cipher.h"
#include "util.h"
#include "log.h"
#include <stdbool.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define LP_PKEY_PREFIX "LastPassPrivateKey<"
#define LP_PKEY_SUFFIX ">LastPassPrivateKey"

char *cipher_rsa_decrypt(const unsigned char *ciphertext, size_t len, const struct private_key *private_key)
{
	PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	BIO *memory = NULL;
	char *ret = NULL;

	if (!len)
		return NULL;

	memory = BIO_new(BIO_s_mem());
	if (BIO_write(memory, private_key->key, private_key->len) < 0)
		goto out;

	p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(memory, NULL);
	if (!p8inf)
		goto out;
	pkey = EVP_PKCS82PKEY(p8inf);
	if (!pkey)
		goto out;
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
		goto out;

	ret = xcalloc(len + 1, 1);
	if (RSA_private_decrypt(len, (unsigned char *)ciphertext, (unsigned char *)ret, rsa, RSA_PKCS1_OAEP_PADDING) < 0) {
		free(ret);
		ret = NULL;
		goto out;
	}

out:
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	BIO_free_all(memory);
	return ret;
}

int cipher_rsa_encrypt_bytes(const unsigned char *plaintext,
			     size_t in_len,
			     const struct public_key *public_key,
			     unsigned char *out_crypttext, size_t *out_len)
{
	EVP_PKEY *pubkey = NULL;
	RSA *rsa = NULL;
	BIO *memory = NULL;
	int ret;

	if (*out_len < public_key->len) {
		ret = -EINVAL;
		goto out;
	}

	memory = BIO_new(BIO_s_mem());
	ret = BIO_write(memory, public_key->key, public_key->len);
	if (ret < 0)
		goto out;

	ret = -EIO;
	pubkey = d2i_PUBKEY_bio(memory, NULL);
	if (!pubkey)
		goto out;

	rsa = EVP_PKEY_get1_RSA(pubkey);
	if (!rsa)
		goto out;

	ret = RSA_public_encrypt(in_len, plaintext,
			         out_crypttext,
			         rsa, RSA_PKCS1_OAEP_PADDING);
	if (ret < 0)
		goto out;

	*out_len = ret;
	ret = 0;

out:
	EVP_PKEY_free(pubkey);
	RSA_free(rsa);
	BIO_free_all(memory);
	return ret;
}

int cipher_rsa_encrypt(const char *plaintext,
		       const struct public_key *public_key,
		       unsigned char *out_crypttext, size_t *out_len)
{
	return cipher_rsa_encrypt_bytes((unsigned char *) plaintext,
					strlen(plaintext),
					public_key, out_crypttext, out_len);
}

struct aes_layout {
	enum cipher_aes_mode mode;
	unsigned char marker;
	size_t iv_len;
	size_t min_data_len;
	size_t data_multiple;
};

/* marker + iv + data; legacy ECB has no marker and is handled separately */
static const struct aes_layout aes_layouts[] = {
	{ CIPHER_AES_GCM, CIPHER_MARKER_GCM, AES_GCM_IV_LEN, AES_GCM_TAG_LEN, 1 },
	{ CIPHER_AES_CBC, CIPHER_MARKER_CBC, AES_BLOCK_SIZE, AES_BLOCK_SIZE, AES_BLOCK_SIZE },
};

static const struct aes_layout *layout_of_marker(unsigned char marker)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(aes_layouts); i++) {
		if (aes_layouts[i].marker == marker)
			return &aes_layouts[i];
	}
	return NULL;
}

bool cipher_is_marker(unsigned char byte)
{
	return layout_of_marker(byte) != NULL;
}

/* structural match on raw bytes: marker, then iv, then whole data */
static const struct aes_layout *layout_fitting(const unsigned char *ciphertext, size_t len)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(aes_layouts); i++) {
		const struct aes_layout *layout = &aes_layouts[i];
		size_t header = 1 + layout->iv_len;

		if (len >= header + layout->min_data_len &&
		    ciphertext[0] == layout->marker &&
		    (len - header) % layout->data_multiple == 0)
			return layout;
	}
	return NULL;
}

static bool is_aes256_ecb(size_t len)
{
	return len && len % AES_BLOCK_SIZE == 0;
}

/*
 * Structural guess only. An undecryptable legacy ECB item starting with '#'
 * is labelled GCM and re-encoded as '#iv|data' (accepted cross-client risk).
 */
static enum cipher_aes_mode cipher_aes_mode_of(const unsigned char *ciphertext, size_t len)
{
	const struct aes_layout *layout = layout_fitting(ciphertext, len);

	return layout ? layout->mode : CIPHER_AES_ECB;
}

static char *aes256_padded_decrypt(const EVP_CIPHER *cipher, const unsigned char *iv,
				   const unsigned char *data, size_t len,
				   const unsigned char key[KDF_HASH_LEN])
{
	EVP_CIPHER_CTX *ctx;
	char *plaintext;
	size_t buf_len = len + AES_BLOCK_SIZE + 1;
	size_t ptext_len;
	int out_len;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return NULL;

	plaintext = xcalloc(buf_len, 1);
	if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
		goto error;
	if (!EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &out_len, data, len))
		goto error;
	ptext_len = out_len;
	if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)(plaintext + ptext_len), &out_len))
		goto error;
	ptext_len += out_len;
	plaintext[ptext_len] = '\0';
	EVP_CIPHER_CTX_free(ctx);
	return plaintext;

error:
	EVP_CIPHER_CTX_free(ctx);
	secure_clear(plaintext, buf_len);
	free(plaintext);
	return NULL;
}

static char *aes256_gcm_decrypt(const unsigned char *ciphertext, size_t len,
				const unsigned char key[KDF_HASH_LEN], bool *auth_failed)
{
	const unsigned char *iv = ciphertext + 1;
	const unsigned char *data = iv + AES_GCM_IV_LEN;
	const unsigned char *tag;
	size_t data_len;
	EVP_CIPHER_CTX *ctx;
	char *plaintext;
	size_t ptext_len;
	int out_len;

	*auth_failed = false;
	if (len < AES_GCM_MIN_LEN)
		return NULL;
	data_len = len - AES_GCM_MIN_LEN;
	tag = data + data_len;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return NULL;

	plaintext = xcalloc(data_len + 1, 1);
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		goto error;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) <= 0)
		goto error;
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		goto error;
	if (!EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &out_len, data, data_len))
		goto error;
	ptext_len = out_len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void *)tag) <= 0)
		goto error;
	if (EVP_DecryptFinal_ex(ctx, (unsigned char *)(plaintext + ptext_len), &out_len) <= 0) {
		*auth_failed = true;
		goto error;
	}
	ptext_len += out_len;
	plaintext[ptext_len] = '\0';
	EVP_CIPHER_CTX_free(ctx);
	return plaintext;

error:
	EVP_CIPHER_CTX_free(ctx);
	secure_clear(plaintext, data_len + 1);
	free(plaintext);
	return NULL;
}

static char *aes256_decrypt(const unsigned char *ciphertext, size_t len,
			    const unsigned char key[KDF_HASH_LEN],
			    bool allow_ecb, enum cipher_aes_mode *mode)
{
	const struct aes_layout *layout = layout_fitting(ciphertext, len);
	enum cipher_aes_mode found = layout ? layout->mode : CIPHER_AES_ECB;
	bool auth_failed = false;
	char *plaintext = NULL;

	if (layout && layout->mode == CIPHER_AES_GCM)
		plaintext = aes256_gcm_decrypt(ciphertext, len, key, &auth_failed);
	else if (layout)
		plaintext = aes256_padded_decrypt(EVP_aes_256_cbc(), ciphertext + 1,
						  ciphertext + 1 + layout->iv_len,
						  len - 1 - layout->iv_len, key);
	if (!plaintext && allow_ecb && is_aes256_ecb(len)) {
		plaintext = aes256_padded_decrypt(EVP_aes_256_ecb(), NULL, ciphertext, len, key);
		if (plaintext)
			found = CIPHER_AES_ECB;
	}
	if (!plaintext && auth_failed)
		lpass_log(LOG_WARNING, "AES-GCM authentication failed\n");

	if (mode)
		*mode = found;
	return plaintext;
}

/*
 * The binary blob carries raw ciphertext, where legacy ECB data may start
 * with '#' or '!', so try each structurally possible mode in turn.
 *
 * A '#' item failing the GCM tag is retried as ECB when len % 16 == 0, like
 * web and mobile do (accepted risk, no way to disambiguate). Such a failure
 * decrypts to garbage ~1/256 of the time, without the auth failure warning.
 */
char *cipher_aes_decrypt_mode(const unsigned char *ciphertext, size_t len,
			      const unsigned char key[KDF_HASH_LEN],
			      enum cipher_aes_mode *mode)
{
	return aes256_decrypt(ciphertext, len, key, true, mode);
}

char *cipher_aes_decrypt(const unsigned char *ciphertext, size_t len, const unsigned char key[KDF_HASH_LEN])
{
	return cipher_aes_decrypt_mode(ciphertext, len, key, NULL);
}

static
size_t cipher_aes_encrypt_bytes(const unsigned char *bytes, size_t len,
				const unsigned char key[KDF_HASH_LEN],
				const unsigned char *iv,
				unsigned char **out)
{
	EVP_CIPHER_CTX *ctx;
	int out_len;
	size_t ret_len = 0;
	unsigned char *ctext;

	ctext = *out;
	if (!ctext)
		ctext = xcalloc(len + AES_BLOCK_SIZE * 2 + 1, 1);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto error;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		goto error;

	if (!EVP_EncryptUpdate(ctx, ctext, &out_len, bytes, len))
		goto error;

	ret_len += out_len;
	if (!EVP_EncryptFinal_ex(ctx, ctext + ret_len, &out_len))
		goto error;
	ret_len += out_len;

	EVP_CIPHER_CTX_free(ctx);
	*out = ctext;
	return ret_len;

error:
	EVP_CIPHER_CTX_free(ctx);
	if (!*out)
		free(ctext);
	die("Failed to encrypt data.");

}

size_t cipher_aes_encrypt(const char *plaintext,
			  const unsigned char key[KDF_HASH_LEN],
			  unsigned char **out)
{
	unsigned char *ciphertext;
	unsigned char *tmp;
	unsigned char iv[AES_BLOCK_SIZE];
	int in_len;
	size_t len;

	if (!RAND_bytes(iv, AES_BLOCK_SIZE))
		die("Could not generate random bytes for CBC IV.");

	in_len = strlen(plaintext);

	ciphertext = xcalloc(in_len + AES_BLOCK_SIZE * 2 + 1, 1);
	ciphertext[0] = CIPHER_MARKER_CBC;
	len = 1;

	memcpy(ciphertext + len, iv, AES_BLOCK_SIZE);
	len += AES_BLOCK_SIZE;

	tmp = ciphertext + len;
	len += cipher_aes_encrypt_bytes((unsigned char *)plaintext, in_len,
					key, iv, &tmp);

	*out = ciphertext;
	return len;
}

static char *base64(const unsigned char *bytes, size_t len)
{
	BIO *memory, *b64;
	BUF_MEM *buffer;
	char *output;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	memory = BIO_new(BIO_s_mem());
	if (!b64 || !memory)
		goto error;
	b64 = BIO_push(b64, memory);
	if (!b64)
		goto error;
	if (BIO_write(b64, bytes, len) < 0 || BIO_flush(b64) < 0)
		goto error;

	BIO_get_mem_ptr(b64, &buffer);
	output = xmalloc(buffer->length + 1);
	memcpy(output, buffer->data, buffer->length);
	output[buffer->length] = '\0';

	BIO_free_all(b64);
	return output;

error:
	die("Could not base64 the given bytes.");
}

static char *base64_with_iv(const unsigned char *bytes, size_t len, size_t iv_len)
{
	_cleanup_free_ char *iv = base64(bytes + 1, iv_len);
	_cleanup_free_ char *data = base64(bytes + 1 + iv_len, len - 1 - iv_len);
	char *output;

	xasprintf(&output, "%c%s|%s", bytes[0], iv, data);
	return output;
}

char *cipher_base64_mode(const unsigned char *bytes, size_t len, enum cipher_aes_mode mode)
{
	const struct aes_layout *layout = layout_fitting(bytes, len);

	if (layout && layout->mode == mode)
		return base64_with_iv(bytes, len, layout->iv_len);
	return base64(bytes, len);
}

char *cipher_base64(const unsigned char *bytes, size_t len)
{
	return cipher_base64_mode(bytes, len, cipher_aes_mode_of(bytes, len));
}

static size_t unbase64_noexit(const char *bytes, unsigned char **unbase64)
{
	size_t len;
	int nread;
	BIO *memory, *b64;
	unsigned char *buffer;

	len = strlen(bytes);
	if (!len)
		return 0;
	b64 = BIO_new(BIO_f_base64());
	memory = BIO_new_mem_buf((char *)bytes, len);
	if (!b64 || !memory) {
		BIO_free_all(b64);
		BIO_free_all(memory);
		return 0;
	}
	b64 = BIO_push(b64, memory);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	buffer = xcalloc(len + 1, 1);
	nread = BIO_read(b64, buffer, len);
	BIO_free_all(b64);
	if (nread <= 0) {
		free(buffer);
		return 0;
	}
	buffer[nread] = '\0';

	*unbase64 = buffer;
	return nread;
}

size_t unbase64(const char *bytes, unsigned char **unbase64)
{
	size_t len = unbase64_noexit(bytes, unbase64);

	if (!len)
		die("Could not unbase64 the given bytes.");
	return len;
}

static size_t unbase64_with_iv(const char *ciphertext, const struct aes_layout *layout,
			       unsigned char **b64data)
{
	_cleanup_free_ char *copy = NULL;
	_cleanup_free_ unsigned char *iv = NULL;
	_cleanup_free_ unsigned char *data = NULL;
	unsigned char *unbase64_ciphertext = NULL;
	char *pipe;
	size_t iv_len, data_len, len;

	copy = xstrdup(&ciphertext[1]);
	pipe = strchr(copy, '|');
	if (!pipe)
		return 0;
	*pipe = '\0';
	if (!*copy || !pipe[1])
		return 0;
	iv_len = unbase64_noexit(copy, &iv);
	if (iv_len != layout->iv_len)
		return 0;
	data_len = unbase64_noexit(pipe + 1, &data);
	if (data_len < layout->min_data_len || data_len % layout->data_multiple)
		return 0;
	len = 1 + iv_len + data_len;
	unbase64_ciphertext = xcalloc(len, 1);
	unbase64_ciphertext[0] = ciphertext[0];
	memcpy(&unbase64_ciphertext[1], iv, iv_len);
	memcpy(&unbase64_ciphertext[1 + iv_len], data, data_len);

	*b64data = unbase64_ciphertext;
	return len;
}

size_t cipher_unbase64(const char *ciphertext, unsigned char **b64data)
{
	const struct aes_layout *layout;

	if (!strlen(ciphertext))
		return 0;

	layout = layout_of_marker(ciphertext[0]);
	if (layout)
		return unbase64_with_iv(ciphertext, layout, b64data);
	return unbase64(ciphertext, b64data);
}

char *cipher_aes_decrypt_base64(const char *ciphertext, const unsigned char key[KDF_HASH_LEN])
{
	_cleanup_free_ unsigned char *unbase64_ciphertext = NULL;
	size_t len;

	len = cipher_unbase64(ciphertext, &unbase64_ciphertext);
	if (!len)
		return NULL;

	/* a marker in text form fixes the mode, so never retry as ECB */
	return aes256_decrypt(unbase64_ciphertext, len, key,
			      !cipher_is_marker(ciphertext[0]), NULL);
}

char *encrypt_and_base64(const char *str, unsigned const char key[KDF_HASH_LEN])
{
	unsigned char *intermediate = NULL;
	char *base64 = NULL;
	size_t len;

	base64 = xstrdup(str);
	if (!*base64)
		return base64;

	len = cipher_aes_encrypt(base64, key, &intermediate);
	free(base64);
	base64 = cipher_base64(intermediate, len);
	free(intermediate);
	return base64;
}

/*
 * Decrypt the LastPass sharing RSA private key.  The key has start_str
 * and end_str prepended / appended before encryption, and the result
 * is encrypted with the AES key.
 *
 * On success, the resulting key is stored in out_key and mlock()ed.
 * If there is a non-fatal error (or no key), the resulting structure
 * will have len = 0.  Returns false on such an error, true on success
 * or when there is no key.
 */
bool cipher_decrypt_private_key(const char *key_hex,
				unsigned const char key[KDF_HASH_LEN],
				struct private_key *out_key)
{
	size_t len;
	_cleanup_free_ unsigned char *encrypted_key = NULL;
	_cleanup_free_ char *decrypted_key = NULL;
	unsigned char *encrypted_key_start;
	char *start, *end;
	unsigned char *dec_key = NULL;
	int ret;

	#define start_str LP_PKEY_PREFIX
	#define end_str LP_PKEY_SUFFIX

	memset(out_key, 0, sizeof(*out_key));

	len = strlen(key_hex);
	if (!len)
		return true;

	if (cipher_is_marker(key_hex[0])) {
		/* v2 (CBC) / v3 (GCM) format */
		decrypted_key = cipher_aes_decrypt_base64(
			key_hex, key);
	} else {
		if (len % 2 != 0)
			die("Key hex in wrong format.");
		len /= 2;

		/* v1 format */
		len += 16 /* IV */ + 1 /* bang symbol */;
		encrypted_key = xcalloc(len + 1, 1);
		encrypted_key[0] = CIPHER_MARKER_CBC;
		memcpy(&encrypted_key[1], key, 16);
		encrypted_key_start = &encrypted_key[17];
		hex_to_bytes(key_hex, &encrypted_key_start);
		decrypted_key = cipher_aes_decrypt(encrypted_key, len, key);
	}

	if (!decrypted_key) {
		warn("Could not decrypt private key.");
		return false;
	}

	start = strstr(decrypted_key, start_str);
	end = strstr(decrypted_key, end_str);
	if (!start || !end || end <= start) {
		warn("Could not decode decrypted private key.");
		return false;
	}

	start += strlen(start_str);
	*end = '\0';

	ret = hex_to_bytes(start, &dec_key);
	if (ret)
		die("Invalid private key after decryption and decoding.");

	out_key->key = dec_key;
	out_key->len = strlen(start) / 2;
	mlock(out_key->key, out_key->len);

	#undef start_str
	#undef end_str
	return true;
}

/*
 * Encrypt RSA sharing key.  Encrypted key is returned as a base64 string.
 */
char *cipher_encrypt_private_key(struct private_key *private_key,
				 unsigned const char key[KDF_HASH_LEN])
{
	unsigned char *key_ptext;
	unsigned char *ctext = NULL;
	char *key_hex_dst;
	char *encrypted_base64 = NULL;
	size_t len, ctext_len, hex_len;

	if (!private_key->len)
		return xstrdup("");

	hex_len = private_key->len * 2;
	len = strlen(LP_PKEY_PREFIX) + hex_len + strlen(LP_PKEY_SUFFIX);

	key_ptext = xcalloc(len + 1, 1);
	memcpy(key_ptext, LP_PKEY_PREFIX, strlen(LP_PKEY_PREFIX));

	key_hex_dst = (char *) key_ptext + strlen(LP_PKEY_PREFIX);
	bytes_to_hex(private_key->key, &key_hex_dst, private_key->len);

	memcpy(key_ptext + strlen(LP_PKEY_PREFIX) + hex_len,
	       LP_PKEY_SUFFIX, strlen(LP_PKEY_SUFFIX));
	
	ctext_len = cipher_aes_encrypt(key_ptext, key, &ctext);

	encrypted_base64 = cipher_base64(ctext, ctext_len);

	free(ctext);
	free(key_ptext);

	return encrypted_base64;
}

/*
 * Get hex-encoded sha256() of a buffer.
 */
char *cipher_sha256_hex(unsigned char *bytes, size_t len)
{
	char *tmp = NULL;
	SHA256_CTX sha256;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	if (!SHA256_Init(&sha256))
		goto die;
	if (!SHA256_Update(&sha256, bytes, len))
		goto die;
	if (!SHA256_Final(hash, &sha256))
		goto die;

	bytes_to_hex(hash, &tmp, sizeof(hash));
	return tmp;
die:
	die("SHA-256 hash failed");
}

char *cipher_sha256_b64(unsigned char *bytes, size_t len)
{
	_cleanup_free_ unsigned char *hash_raw = NULL;
	_cleanup_free_ char *hash_hex = NULL;

	hash_hex = cipher_sha256_hex(bytes, len);
	hex_to_bytes(hash_hex, &hash_raw);
	return base64(hash_raw, strlen(hash_hex) / 2);
}

/*
 * Get hex-encoded sha256() for multiple arguments.
 */
char *cipher_multi_sha256_hex(int num_args, ...)
{
	va_list args;
	char *hash_hex = NULL;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	const EVP_MD *md_sha256;
	EVP_MD_CTX *sha256_ctx;

	va_start(args, num_args);

	sha256_ctx = EVP_MD_CTX_create();
	md_sha256 = EVP_sha256();
	if (!md_sha256)
		goto error;

	if (!EVP_DigestInit_ex(sha256_ctx, md_sha256, NULL))
		goto error;

	for (int i = 0; i < num_args; i++) {
		char *arg = va_arg(args, char *);
		if (!EVP_DigestUpdate(sha256_ctx, arg, strlen(arg)))
			goto error;
	}
	
	if (!EVP_DigestFinal_ex(sha256_ctx, hash, 0))
		goto error;

	bytes_to_hex(hash, &hash_hex, sizeof(hash));
	EVP_MD_CTX_free(sha256_ctx);

	return hash_hex;

error:
	EVP_MD_CTX_free(sha256_ctx);
	die("SHA-256 hash failed");
}
