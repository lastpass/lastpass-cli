/*
 * encryption and decryption routines
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
#include "cipher.h"
#include "util.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <string.h>
#include <openssl/err.h>

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
	if (p8inf->broken)
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

int cipher_rsa_encrypt(const char *plaintext,
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

	ret = RSA_public_encrypt(strlen(plaintext), (unsigned char *) plaintext,
			         (unsigned char *) out_crypttext,
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

char *cipher_aes_decrypt(const unsigned char *ciphertext, size_t len, const unsigned char key[KDF_HASH_LEN])
{
	EVP_CIPHER_CTX ctx;
	char *plaintext;
	int out_len;

	if (!len)
		return NULL;

	EVP_CIPHER_CTX_init(&ctx);
	plaintext = xcalloc(len + AES_BLOCK_SIZE + 1, 1);
	if (len >= 33 && len % 16 == 1 && ciphertext[0] == '!') {
		if (!EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, (unsigned char *)(ciphertext + 1)))
			goto error;
		ciphertext += 17;
		len -= 17;
	} else {
		if (!EVP_DecryptInit_ex(&ctx, EVP_aes_256_ecb(), NULL, key, NULL))
			goto error;
	}
	if (!EVP_DecryptUpdate(&ctx, (unsigned char *)plaintext, &out_len, (unsigned char *)ciphertext, len))
		goto error;
	len = out_len;
	if (!EVP_DecryptFinal_ex(&ctx, (unsigned char *)(plaintext + out_len), &out_len))
		goto error;
	len += out_len;
	plaintext[len] = '\0';
	EVP_CIPHER_CTX_cleanup(&ctx);
	return plaintext;

error:
	EVP_CIPHER_CTX_cleanup(&ctx);
	secure_clear(plaintext, len + AES_BLOCK_SIZE + 1);
	free(plaintext);
	return NULL;
}
size_t cipher_aes_encrypt(const char *plaintext, const unsigned char key[KDF_HASH_LEN], char **out)
{
	EVP_CIPHER_CTX ctx;
	char *ciphertext;
	unsigned char iv[AES_BLOCK_SIZE];
	int out_len;
	int in_len;
	size_t len;

	if (!RAND_bytes(iv, AES_BLOCK_SIZE))
		die("Could not generate random bytes for CBC IV.");

	in_len = strlen(plaintext);

	EVP_CIPHER_CTX_init(&ctx);
	ciphertext = xcalloc(in_len + AES_BLOCK_SIZE * 2 + 1, 1);

	ciphertext[0] = '!';
	len = 1;

	memcpy(ciphertext + len, iv, AES_BLOCK_SIZE);
	len += AES_BLOCK_SIZE;

	if (!EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv))
		goto error;
	if (!EVP_EncryptUpdate(&ctx, (unsigned char *)(ciphertext + len), &out_len, (unsigned char *)plaintext, in_len))
		goto error;
	len += out_len;
	if (!EVP_EncryptFinal_ex(&ctx, (unsigned char *)(ciphertext + len), &out_len))
		goto error;
	len += out_len;
	EVP_CIPHER_CTX_cleanup(&ctx);

	*out = ciphertext;
	return len;

error:
	EVP_CIPHER_CTX_cleanup(&ctx);
	free(ciphertext);
	die("Failed to encrypt data.");
}
static char *base64(const char *bytes, size_t len)
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

char *cipher_base64(const char *bytes, size_t len)
{
	_cleanup_free_ char *iv = NULL;
	_cleanup_free_ char *data = NULL;
	char *output;

	if (len >= 33 && bytes[0] == '!' && len % 16 == 1) {
		iv = base64(bytes + 1, 16);
		data = base64(bytes + 17, len - 17);
		xasprintf(&output, "!%s|%s", iv, data);
		return output;
	}
	return base64(bytes, len);
}

static size_t unbase64(const char *bytes, unsigned char **unbase64)
{
	size_t len;
	BIO *memory, *b64;
	unsigned char *buffer;

	len = strlen(bytes);
	if (!len)
		goto error;
	b64 = BIO_new(BIO_f_base64());
	memory = BIO_new_mem_buf((char *)bytes, len);
	if (!b64 || !memory)
		goto error;
	b64 = BIO_push(b64, memory);
	if (!b64)
		goto error;
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	buffer = xcalloc(len + 1, 1);
	len = BIO_read(b64, buffer, len);
	if ((int)len <= 0)
		goto error;
	buffer[len] = '\0';

	BIO_free_all(b64);
	*unbase64 = buffer;
	return len;

error:
	die("Could not unbase64 the given bytes.");
}

char *cipher_aes_decrypt_base64(const char *ciphertext, const unsigned char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *copy = NULL;
	_cleanup_free_ unsigned char *iv = NULL;
	_cleanup_free_ unsigned char *data = NULL;
	_cleanup_free_ unsigned char *unbase64_ciphertext = NULL;
	char *pipe;
	size_t iv_len, data_len, len;

	if (!strlen(ciphertext))
		return NULL;

	if (ciphertext[0] == '!') {
		copy = xstrdup(&ciphertext[1]);
		pipe = strchr(copy, '|');
		if (!pipe)
			return NULL;
		*pipe = '\0';
		iv_len = unbase64(copy, &iv);
		data_len = unbase64(pipe + 1, &data);
		len = iv_len + data_len + 1 /* pound */;
		unbase64_ciphertext = xcalloc(len, 1);
		unbase64_ciphertext[0] = '!';
		memcpy(&unbase64_ciphertext[1], iv, iv_len);
		memcpy(&unbase64_ciphertext[1 + iv_len], data, data_len);
		return cipher_aes_decrypt(unbase64_ciphertext, len, key);
	} else {
		len = unbase64(ciphertext, &data);
		return cipher_aes_decrypt(data, len, key);
	}
}

char *encrypt_and_base64(const char *str, unsigned const char key[KDF_HASH_LEN])
{
	char *intermediate = NULL;
	char *base64 = NULL;
	size_t len;

	base64 = trim(xstrdup(str));
	if (!*base64)
		return base64;

	len = cipher_aes_encrypt(base64, key, &intermediate);
	free(base64);
	base64 = cipher_base64(intermediate, len);
	free(intermediate);
	return base64;
}
