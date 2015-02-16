/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "config.h"
#include "util.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <utime.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>


char *config_path(const char *name)
{
	char *home, *path;
	_cleanup_free_ char *config = NULL;
	struct stat sbuf;
	int ret;

	home = getenv("LPASS_HOME");
	if (home)
		config = xstrdup(home);
	else {
		home = getenv("HOME");
		if (!home)
			die("HOME is not set");

		xasprintf(&config, "%s/.lpass", home);
	}

	ret = stat(config, &sbuf);
	if ((ret == -1 && errno == ENOENT) || !S_ISDIR(sbuf.st_mode)) {
		unlink(config);
		if (mkdir(config, 0700) < 0)
			die_errno("mkdir(%s)", config);
	} else if (ret == -1)
		die_errno("stat(%s)", config);

	xasprintf(&path, "%s/%s", config, name);

	return path;
}

FILE *config_fopen(const char *name, const char *mode)
{
	_cleanup_free_ char *path = config_path(name);
	return fopen(path, mode);
}

void config_touch(const char *name)
{
	_cleanup_free_ char *path = NULL;
	path = config_path(name);
	if (utime(path, NULL) < 0)
		die_errno("utime");
}

bool config_exists(const char *name)
{
	_cleanup_free_ char *path = NULL;
	struct stat sbuf;

	path = config_path(name);
	return stat(path, &sbuf) != -1;
}

time_t config_mtime(const char *name)
{
	_cleanup_free_ char *path = NULL;
	struct stat sbuf;

	path = config_path(name);
	if (stat(path, &sbuf) < 0)
		return 0;

	return sbuf.st_mtime;
}

bool config_unlink(const char *name)
{
	_cleanup_free_ char *path = config_path(name);
	return unlink(path) == 0;
}

void config_write_string(const char *name, const char *string)
{
	config_write_buffer(name, string, strlen(string));
}

void config_write_buffer(const char *name, const char *buffer, size_t len)
{
	_cleanup_free_ char *tempname = NULL;
	_cleanup_free_ char *finalpath = config_path(name);
	int tempfd;
	FILE *tempfile = NULL;

	xasprintf(&tempname, "%s.XXXXXX", finalpath);
	tempfd = mkstemp(tempname);
	if (tempfd < 0)
		die_errno("mkstemp");
	tempfile = fdopen(tempfd, "w");
	if (!tempfile)
		goto error;
	if (fwrite(buffer, 1, len, tempfile) != len)
		goto error;
	fclose(tempfile);
	tempfile = NULL;
	if (rename(tempname, finalpath) < 0)
		goto error;
	return;

error:
	tempfd = errno;
	if (tempfile)
		fclose(tempfile);
	unlink(tempname);
	errno = tempfd;
	die_errno("config-%s", name);
}

char *config_read_string(const char *name)
{
	_cleanup_free_ char *buffer = NULL;
	size_t len = config_read_buffer(name, &buffer);

	if (!buffer)
		return NULL;

	return xstrndup(buffer, len);
}

size_t config_read_buffer(const char *name, char **out)
{
	_cleanup_fclose_ FILE *file = NULL;
	char *buffer;
	size_t len, read;

	file = config_fopen(name, "r");
	if (!file) {
		*out = NULL;
		return 0;
	}

	for (len = 0, buffer = xmalloc(8192); ; buffer = xrealloc(buffer, len + 8192)) {
		read = fread(buffer + len, 1, 8192, file);
		len += read;
		if (read != 8192) {
			if (ferror(file))
				die_errno("fread(config-%s)", name);
			break;
		}
	}

	*out = buffer;
	return len;
}

/*
 * ciphertext = IV | aes-256-cbc(plaintext, key)
 * authenticated-ciphertext = HMAC-SHA256(ciphertext, key) | ciphertext
 *
 * These two functions work with `authenticated-ciphertext`.
 */

static size_t encrypt_buffer(const char *buffer, size_t in_len, unsigned const char key[KDF_HASH_LEN], char **out)
{
	EVP_CIPHER_CTX ctx;
	char *ciphertext;
	unsigned char iv[AES_BLOCK_SIZE];
	int out_len;
	unsigned int hmac_len;
	size_t len;

	if (!RAND_bytes(iv, AES_BLOCK_SIZE))
		die("Could not generate random bytes for CBC IV.");

	EVP_CIPHER_CTX_init(&ctx);
	ciphertext = xcalloc(in_len + AES_BLOCK_SIZE * 2 + SHA256_DIGEST_LENGTH, 1);

	len = SHA256_DIGEST_LENGTH;
	memcpy(ciphertext + len, iv, AES_BLOCK_SIZE);
	len += AES_BLOCK_SIZE;

	if (!EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv))
		goto error;
	if (!EVP_EncryptUpdate(&ctx, (unsigned char *)(ciphertext + len), &out_len, (unsigned char *)buffer, in_len))
		goto error;
	len += out_len;
	if (!EVP_EncryptFinal_ex(&ctx, (unsigned char *)(ciphertext + len), &out_len))
		goto error;
	len += out_len;
	EVP_CIPHER_CTX_cleanup(&ctx);

	if (!HMAC(EVP_sha256(), key, KDF_HASH_LEN, (unsigned char *)(ciphertext + SHA256_DIGEST_LENGTH), len - SHA256_DIGEST_LENGTH, (unsigned char *)ciphertext, &hmac_len))
		goto error;

	*out = ciphertext;
	return len;

error:
	EVP_CIPHER_CTX_cleanup(&ctx);
	free(ciphertext);
	die("Failed to encrypt data.");

}

static size_t decrypt_buffer(const char *buffer, size_t in_len, unsigned const char key[KDF_HASH_LEN], char **out)
{
	EVP_CIPHER_CTX ctx;
	char *plaintext = NULL;
	int out_len;
	unsigned int hmac_len;
	size_t len;
	unsigned char hmac[SHA256_DIGEST_LENGTH];

	EVP_CIPHER_CTX_init(&ctx);

	if (in_len < (SHA256_DIGEST_LENGTH + AES_BLOCK_SIZE * 2))
		goto error;

	if (!HMAC(EVP_sha256(), key, KDF_HASH_LEN, (unsigned char *)(buffer + SHA256_DIGEST_LENGTH), in_len - SHA256_DIGEST_LENGTH, hmac, &hmac_len))
		goto error;
	if (CRYPTO_memcmp(hmac, buffer, SHA256_DIGEST_LENGTH))
		goto error;

	plaintext = xcalloc(in_len + AES_BLOCK_SIZE, 1);
	if (!EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, (unsigned char *)(buffer + SHA256_DIGEST_LENGTH)))
		goto error;
	if (!EVP_DecryptUpdate(&ctx, (unsigned char *)plaintext, &out_len, (unsigned char *)(buffer + SHA256_DIGEST_LENGTH + AES_BLOCK_SIZE), in_len - SHA256_DIGEST_LENGTH - AES_BLOCK_SIZE))
		goto error;
	len = out_len;
	if (!EVP_DecryptFinal_ex(&ctx, (unsigned char *)(plaintext + out_len), &out_len))
		goto error;
	len += out_len;
	EVP_CIPHER_CTX_cleanup(&ctx);
	*out = plaintext;
	return len;

error:
	EVP_CIPHER_CTX_cleanup(&ctx);
	free(plaintext);
	*out = NULL;
	return 0;
}

void config_write_encrypted_string(const char *name, const char *string, unsigned const char key[KDF_HASH_LEN])
{
	config_write_encrypted_buffer(name, string, strlen(string), key);
}

void config_write_encrypted_buffer(const char *name, const char *buffer, size_t len, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *encrypted_buffer = NULL;

	len = encrypt_buffer(buffer, len, key, &encrypted_buffer);
	config_write_buffer(name, encrypted_buffer, len);
}

char *config_read_encrypted_string(const char *name, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *buffer = NULL;
	size_t len = config_read_encrypted_buffer(name, &buffer, key);

	if (!buffer)
		return NULL;

	return xstrndup(buffer, len);
}

size_t config_read_encrypted_buffer(const char *name, char **buffer, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *encrypted_buffer = NULL;
	size_t len;

	len = config_read_buffer(name, &encrypted_buffer);
	if (!encrypted_buffer) {
		*buffer = NULL;
		return 0;
	}

	return decrypt_buffer(encrypted_buffer, len, key, buffer);
}
