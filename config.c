/*
 * configuration file handling
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

/*
 * Map well-known pathnames to their configuration type.
 */
struct pathname_type_tuple {
	char *name;
	enum config_type type;
};

struct pathname_type_tuple pathname_type_lookup[] = {
	{ "env", CONFIG_CONFIG },
	{ "blob", CONFIG_DATA },
	{ "iterations", CONFIG_DATA },
	{ "username", CONFIG_DATA },
	{ "verify", CONFIG_DATA },
	{ "plaintext_key", CONFIG_DATA },
	{ "trusted_id", CONFIG_DATA },
	{ "session_uid", CONFIG_DATA },
	{ "session_sessionid", CONFIG_DATA },
	{ "session_token", CONFIG_DATA },
	{ "session_privatekey", CONFIG_DATA },
	{ "session_server", CONFIG_DATA },
	{ "lpass.log", CONFIG_DATA },
	{ "agent.sock", CONFIG_RUNTIME },
	{ "uploader.pid", CONFIG_RUNTIME },
};

char *config_type_to_xdg[] = {
	[CONFIG_DATA] = "XDG_DATA_HOME",
	[CONFIG_CONFIG] = "XDG_CONFIG_HOME",
	[CONFIG_RUNTIME] = "XDG_RUNTIME_DIR",
};

static
char *get_xdg_dir(const char *xdg_var)
{
	char *home;
	char *retstr = NULL;

	if (getenv(xdg_var))
		return xstrdup(getenv(xdg_var));

	/*
	 * $XDG var not set in environment; decide whether
	 * to use backups locations based on existence of
	 * $XDG_RUNTIME_DIR.
	 */
	if (!getenv("XDG_RUNTIME_DIR"))
		return NULL;

	home = getenv("HOME");
	if (!home)
		return NULL;

	if (!strcmp(xdg_var, "XDG_DATA_HOME"))
		xasprintf(&retstr, "%s/.local/share", home);
	else if (!strcmp(xdg_var, "XDG_CONFIG_HOME"))
		xasprintf(&retstr, "%s/.config", home);

	return retstr;
}

/*
 * Get the path to a config file given its name and the type of file.
 *
 * lpass looks for files in the following directories:
 *
 * First, if $LPASS_HOME is set, everything goes there.
 *
 * After that, if it is a persistent, user-specific data file,
 * it goes in $XDG_DATA_HOME/lpass.
 *
 * If a configuration item, it goes in $XDG_CONFIG_HOME.
 *
 * If a purely runtime item (socket, pidfile, etc) it goes in
 * $XDG_RUNTIME_HOME.
 *
 * If none of the $XDG environment variables are set, fall-back
 * to ~/.lpass.
 */
static
char *config_path_for_type(enum config_type type, const char *name)
{
	char *home, *path, *xdg_env;
	_cleanup_free_ char *config = NULL;
	_cleanup_free_ char *xdg_dir = NULL;
	struct stat sbuf;
	int ret;

	xdg_env = config_type_to_xdg[type];

	home = getenv("LPASS_HOME");
	if (home)
		config = xstrdup(home);
	else if ((xdg_dir = get_xdg_dir(xdg_env))) {
		xasprintf(&config, "%s/lpass", xdg_dir);
	} else {
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


enum config_type config_path_type(const char *name)
{
	unsigned int i;

	/* aliases are config files */
	if (!strncmp(name, "alias", 5)) {
		return CONFIG_CONFIG;
	}

	/* lock files are runtime */
	if (strlen(name) >= 5 && !strcmp(name + strlen(name) - 5, ".lock")) {
		return CONFIG_RUNTIME;
	}

	/* categorized this configuration file by name? */
	for (i=0; i < ARRAY_SIZE(pathname_type_lookup); i++) {
		if (!strcmp(name, pathname_type_lookup[i].name)) {
			return pathname_type_lookup[i].type;
		}
	}

	/* everything else is config_data */
	return CONFIG_DATA;
}

char *config_path(const char *name)
{
	return config_path_for_type(config_path_type(name), name);
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
		die_errno("mkstemp(%s)", tempname);
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
	size_t len = config_read_buffer(name, (unsigned char **) &buffer);

	if (!buffer)
		return NULL;

	return xstrndup(buffer, len);
}

size_t config_read_buffer(const char *name, unsigned char **out)
{
	_cleanup_fclose_ FILE *file = NULL;
	unsigned char *buffer;
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
	EVP_CIPHER_CTX *ctx;
	char *ciphertext;
	unsigned char iv[AES_BLOCK_SIZE];
	int out_len;
	unsigned int hmac_len;
	size_t len;

	if (!RAND_bytes(iv, AES_BLOCK_SIZE))
		die("Could not generate random bytes for CBC IV.");

	ciphertext = xcalloc(in_len + AES_BLOCK_SIZE * 2 + SHA256_DIGEST_LENGTH, 1);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto error;

	len = SHA256_DIGEST_LENGTH;
	memcpy(ciphertext + len, iv, AES_BLOCK_SIZE);
	len += AES_BLOCK_SIZE;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		goto error;
	if (!EVP_EncryptUpdate(ctx, (unsigned char *)(ciphertext + len), &out_len, (unsigned char *)buffer, in_len))
		goto error;
	len += out_len;
	if (!EVP_EncryptFinal_ex(ctx, (unsigned char *)(ciphertext + len), &out_len))
		goto error;
	len += out_len;

	if (!HMAC(EVP_sha256(), key, KDF_HASH_LEN, (unsigned char *)(ciphertext + SHA256_DIGEST_LENGTH), len - SHA256_DIGEST_LENGTH, (unsigned char *)ciphertext, &hmac_len))
		goto error;

	EVP_CIPHER_CTX_free(ctx);
	*out = ciphertext;
	return len;

error:
	EVP_CIPHER_CTX_free(ctx);
	free(ciphertext);
	die("Failed to encrypt data.");

}

static size_t decrypt_buffer(const unsigned char *buffer, size_t in_len, unsigned const char key[KDF_HASH_LEN], unsigned char **out)
{
	EVP_CIPHER_CTX *ctx;
	unsigned char *plaintext = NULL;
	int out_len;
	unsigned int hmac_len;
	size_t len;
	unsigned char hmac[SHA256_DIGEST_LENGTH];

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto error;

	if (in_len < (SHA256_DIGEST_LENGTH + AES_BLOCK_SIZE * 2))
		goto error;

	if (!HMAC(EVP_sha256(), key, KDF_HASH_LEN, (unsigned char *)(buffer + SHA256_DIGEST_LENGTH), in_len - SHA256_DIGEST_LENGTH, hmac, &hmac_len))
		goto error;
	if (CRYPTO_memcmp(hmac, buffer, SHA256_DIGEST_LENGTH))
		goto error;

	plaintext = xcalloc(in_len + AES_BLOCK_SIZE, 1);
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, (unsigned char *)(buffer + SHA256_DIGEST_LENGTH)))
		goto error;
	if (!EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &out_len, (unsigned char *)(buffer + SHA256_DIGEST_LENGTH + AES_BLOCK_SIZE), in_len - SHA256_DIGEST_LENGTH - AES_BLOCK_SIZE))
		goto error;
	len = out_len;
	if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)(plaintext + out_len), &out_len))
		goto error;
	len += out_len;
	EVP_CIPHER_CTX_free(ctx);
	*out = plaintext;
	return len;

error:
	EVP_CIPHER_CTX_free(ctx);
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
	size_t len = config_read_encrypted_buffer(name, (unsigned char **) &buffer, key);

	if (!buffer)
		return NULL;

	return xstrndup(buffer, len);
}

size_t config_read_encrypted_buffer(const char *name, unsigned char **buffer, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ unsigned char *encrypted_buffer = NULL;
	size_t len;

	len = config_read_buffer(name, &encrypted_buffer);
	if (!encrypted_buffer) {
		*buffer = NULL;
		return 0;
	}

	return decrypt_buffer(encrypted_buffer, len, key, buffer);
}
