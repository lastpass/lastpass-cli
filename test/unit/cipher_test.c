/*
 * unit tests for encryption and decryption routines
 *
 * Copyright (C) 2014-2026 LastPass.
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
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "../../blob.h"
#include "../../cipher.h"
#include "../../cmd.h"
#include "../../config.h"
#include "../../endpoints.h"
#include "../../feature-flag.h"
#include "../../session.h"
#include "../../util.h"
#include "../../xml.h"

/*
 * Vectors generated with Python `cryptography`, key = bytes 0x00..0x1f.
 * GCM IVs: 12 x 0xa0, 0xa1, 0xa2, 0xa3. CBC IV: 0xb0..0xbf.
 */
#define GCM "#oKCgoKCgoKCgoKCg|adARl+6lPa6ZFs3PzUuV3bGY74DRmUZp2h0vni3sAxLz8c/EZ2pVfQ=="
#define GCM_PTEXT "LastPass GCM test vector"
#define GCM_EMPTY "#oaGhoaGhoaGhoaGh|KBlKGEV7pitgcYdpaL/U/w=="
/* 19-byte plaintext: raw length 48, a multiple of the AES block size like ECB */
#define GCM_AMBIGUOUS "#oqKioqKioqKioqKi|NON6aypPFJl6bHbWURlAT6jJJRgbIsivc6WAATVgE6YaNZo="
#define GCM_AMBIGUOUS_PTEXT "ambiguous-gcm-19chr"
#define CBC "!sLGys7S1tre4ubq7vL2+vw==|7b3LiKoDwit82QExs/+9j/ME1OsZ1N8VLmw70wyyUno="
#define CBC_PTEXT "LastPass CBC test vector"
#define ECB "gIb0dOQQAtl34tFkNJWi1rxS76TBYIuAZuYQ/ijgTAA="
#define ECB_PTEXT "LastPass ECB test vector"
/* ECB ciphertexts whose first raw byte is '#' / '!' */
#define ECB_HASH "I386F6OVaN1OD9T6u6uP3/v53KOT+44s+FrwFzM4ycU="
#define ECB_HASH_PTEXT "66-legacy-ecb-field"
#define ECB_BANG "IS/wBs00qAdwA9OEuazrXWLb+h+fy1hxUGJYiP7zZOQ="
#define ECB_BANG_PTEXT "300-legacy-ecb-field"

#define PK_V1 "f2bea062545b1db528ee1ef6cd99f2c6544773ffbc8089d2dc8edae35ca03ebfe621f3733e1431361ef06b4f9b35f4a8e9dc29595abe2533d8e84d8460f3d45645041de615835f2433a77349c7bd22e4"
#define PK_V2 "!sLGys7S1tre4ubq7vL2+vw==|CM9bO0hkzDbwbAk7JyQh7o9+osyyyp2qjbRyRfvF4ejER4FQ5aN0QGtpNMIOxVJkXoqP/mtuXunzSGD7oIWDnNoPRZTZczJpgJ90L9ASsHg="
#define PK_V3 "#o6Ojo6Ojo6Ojo6Oj|zibqqr5bVmAawlCITgYnNUdOJuIuloFGf7d46FiC7YLsA1V4Jp3vIsddcINFDTiLWDQ7wKhvFuzkfKTodiyi4VFEi3kZPrqKsCvDR/s8eole1JcdEE4="
static const unsigned char pk_bytes[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

static unsigned char key[KDF_HASH_LEN];
static unsigned char wrong_key[KDF_HASH_LEN];
static char *home;
static int failures;

static const struct feature_flag flag_off = { 0 };
static const struct feature_flag flag_on = { .aes_gcm_write_enabled = true };
static const struct feature_flag flag_off_url = { .url_encryption_enabled = true };
static const struct feature_flag flag_on_url = { .url_encryption_enabled = true, .aes_gcm_write_enabled = true };

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

static bool str_eq(const char *actual, const char *expected)
{
	return actual && !strcmp(actual, expected);
}

static int saved_stderr = -1;

static void capture_stderr_begin(void)
{
	_cleanup_free_ char *path = config_path("stderr-capture");
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (fd < 0) {
		perror("open");
		exit(1);
	}
	fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	dup2(fd, STDERR_FILENO);
	close(fd);
}

static char *capture_stderr_end(void)
{
	char *text;

	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);
	text = config_read_string("stderr-capture");
	config_unlink("stderr-capture");
	return text ? text : xstrdup("");
}

static size_t count_substr(const char *haystack, const char *needle)
{
	size_t count = 0;

	for (; (haystack = strstr(haystack, needle)); haystack += strlen(needle))
		count++;
	return count;
}

#define GCM_FAILED "AES-GCM authentication failed"
#define ECB_FALLBACK "AES-GCM tag mismatch, read as legacy AES-ECB"

static void check_decrypts(const char *text, const char *expected)
{
	_cleanup_free_ char *ptext = cipher_aes_decrypt_base64_ex(text, key, NULL);

	CHECK(str_eq(ptext, expected));
}

static void check_raw_decrypts(const char *text, const char *expected, enum cipher_aes_mode expected_mode)
{
	_cleanup_free_ unsigned char *raw = NULL;
	_cleanup_free_ char *ptext = NULL;
	_cleanup_free_ char *encoded = NULL;
	enum cipher_aes_mode mode;
	size_t len;

	len = cipher_unbase64(text, &raw);
	CHECK(len > 0);
	ptext = cipher_aes_decrypt_mode(raw, len, key, &mode, NULL);
	CHECK(str_eq(ptext, expected));
	CHECK(mode == expected_mode);

	encoded = cipher_base64_mode(raw, len, mode);
	CHECK(str_eq(encoded, text));
}

static char *tamper(const char *text, size_t offset_from_end)
{
	_cleanup_free_ unsigned char *raw = NULL;
	size_t len = cipher_unbase64(text, &raw);

	raw[len - 1 - offset_from_end] ^= 0x01;
	return cipher_base64(raw, len);
}

static void test_gcm_decrypt(void)
{
	check_decrypts(GCM, GCM_PTEXT);
	check_decrypts(GCM_EMPTY, "");
	check_decrypts(GCM_AMBIGUOUS, GCM_AMBIGUOUS_PTEXT);

	check_raw_decrypts(GCM, GCM_PTEXT, CIPHER_AES_GCM);
	check_raw_decrypts(GCM_AMBIGUOUS, GCM_AMBIGUOUS_PTEXT, CIPHER_AES_GCM);
}

static void test_legacy_decrypt(void)
{
	check_decrypts(CBC, CBC_PTEXT);
	check_decrypts(ECB, ECB_PTEXT);
	check_raw_decrypts(CBC, CBC_PTEXT, CIPHER_AES_CBC);
	check_raw_decrypts(ECB, ECB_PTEXT, CIPHER_AES_ECB);
}

static void test_ecb_with_marker_byte(void)
{
	check_decrypts(ECB_HASH, ECB_HASH_PTEXT);
	check_decrypts(ECB_BANG, ECB_BANG_PTEXT);
	check_raw_decrypts(ECB_HASH, ECB_HASH_PTEXT, CIPHER_AES_ECB);
	check_raw_decrypts(ECB_BANG, ECB_BANG_PTEXT, CIPHER_AES_ECB);
}

static char *tamper_iv(const char *text)
{
	_cleanup_free_ unsigned char *raw = NULL;
	size_t len = cipher_unbase64(text, &raw);

	raw[1] ^= 0x01;
	return cipher_base64(raw, len);
}

static void test_gcm_tampered(void)
{
	_cleanup_free_ char *bad_tag = tamper(GCM, 0);
	_cleanup_free_ char *bad_data = tamper(GCM, AES_GCM_TAG_LEN);
	_cleanup_free_ char *bad_iv = tamper(GCM, strlen(GCM_PTEXT) + AES_GCM_TAG_LEN);
	_cleanup_free_ unsigned char *raw = NULL;
	size_t len;

	CHECK(bad_tag[0] == '#' && strcmp(bad_tag, GCM));
	CHECK(cipher_aes_decrypt_base64_ex(bad_tag, key, NULL) == NULL);
	CHECK(cipher_aes_decrypt_base64_ex(bad_data, key, NULL) == NULL);
	CHECK(cipher_aes_decrypt_base64_ex(bad_iv, key, NULL) == NULL);

	len = cipher_unbase64(bad_tag, &raw);
	CHECK(cipher_aes_decrypt(raw, len, key) == NULL);
	CHECK(cipher_aes_decrypt(raw, AES_GCM_MIN_LEN - 1, key) == NULL);
}

static void test_gcm_malformed_text(void)
{
	const char *malformed[] = {
		"#abc",
		"#|",
		"#|AAAAAAAAAAAAAAAAAAAAAA==",
		"#oKCgoKCgoKCgoKCg|",
		"#AAAA|AAAAAAAAAAAAAAAAAAAAAA==",
		"#oKCgoKCgoKCgoKCg|AAAA",
		/* invalid base64 must not be fatal: no padding, url-safe alphabet */
		"#oKCgoKCgoKCgoKCg|AAAAAAAAAAAAAAAAAAAAAAA",
		"#oKCgoKCgoKCgoKCg|AAAAAAAAAAAAAAAAAAAAAA_=",
		"!oKCgoKCgoKCgoKCgoKCgoA==|AAAAAAAAAAAAAAAAAAAAAAA",
		/* CBC data that is not a whole number of blocks */
		"!oKCgoKCgoKCgoKCgoKCgoA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		/* no marker: plain base64, garbage must not be fatal either */
		"@@@@",
	};
	unsigned char *raw = NULL;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(malformed); i++) {
		CHECK(cipher_unbase64(malformed[i], &raw) == 0);
		CHECK(cipher_aes_decrypt_base64_ex(malformed[i], key, NULL) == NULL);
	}
}

static void test_truncated_account_chunk(void)
{
	/* ACCT chunk ends right after the group item */
	static const unsigned char truncated[] = {
		'A', 'C', 'C', 'T', 0, 0, 0, 13,
		0, 0, 0, 1, '1',
		0, 0, 0, 0,
		0, 0, 0, 0,
	};
	_cleanup_free_ unsigned char *exact = xcalloc(sizeof(truncated), 1);
	struct blob *parsed;

	memcpy(exact, truncated, sizeof(truncated));
	parsed = blob_parse(exact, sizeof(truncated), key, NULL);
	CHECK(parsed == NULL);
	blob_free(parsed);
}

static void check_ambiguous_tamper_rejected(const char *bad)
{
	_cleanup_free_ unsigned char *raw = NULL;
	_cleanup_free_ char *ptext = NULL;
	enum cipher_aes_mode mode;
	size_t len = cipher_unbase64(bad, &raw);

	CHECK(len % 16 == 0);
	CHECK(cipher_aes_decrypt_base64_ex(bad, key, NULL) == NULL);
	ptext = cipher_aes_decrypt_mode(raw, len, key, &mode, NULL);
	CHECK(ptext == NULL);
	CHECK(mode == CIPHER_AES_GCM);
}

static void test_gcm_ambiguous_tampered(void)
{
	_cleanup_free_ char *bad_tag = tamper(GCM_AMBIGUOUS, 0);
	_cleanup_free_ char *bad_data = tamper(GCM_AMBIGUOUS, AES_GCM_TAG_LEN);
	_cleanup_free_ char *bad_iv = tamper_iv(GCM_AMBIGUOUS);

	check_ambiguous_tamper_rejected(bad_tag);
	check_ambiguous_tamper_rejected(bad_data);
	check_ambiguous_tamper_rejected(bad_iv);
}

static void check_wrong_key_rejected(const char *text)
{
	_cleanup_free_ unsigned char *raw = NULL;
	_cleanup_free_ char *ptext = cipher_aes_decrypt_base64_ex(text, wrong_key, NULL);
	_cleanup_free_ char *raw_ptext = NULL;
	size_t len = cipher_unbase64(text, &raw);

	CHECK(ptext == NULL);
	raw_ptext = cipher_aes_decrypt(raw, len, wrong_key);
	CHECK(raw_ptext == NULL);
}

static void test_wrong_key(void)
{
	const char *vectors[] = {
		GCM, GCM_EMPTY, GCM_AMBIGUOUS, CBC, ECB, ECB_HASH, ECB_BANG,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(vectors); i++)
		check_wrong_key_rejected(vectors[i]);
}

static void check_private_key(const char *key_hex)
{
	struct private_key pk;

	cipher_decrypt_private_key(key_hex, key, &pk);
	CHECK(pk.len == sizeof(pk_bytes));
	CHECK(pk.key && !memcmp(pk.key, pk_bytes, sizeof(pk_bytes)));
	if (pk.key) {
		secure_clear(pk.key, pk.len);
		free(pk.key);
	}
}

static void test_private_key(void)
{
	check_private_key(PK_V1);
	check_private_key(PK_V2);
	check_private_key(PK_V3);
}

static void check_private_key_rejected(const char *key_hex, const unsigned char *k)
{
	struct private_key pk;

	cipher_decrypt_private_key(key_hex, k, &pk);
	CHECK(pk.len == 0);
	CHECK(pk.key == NULL);
}

static void test_private_key_rejected(void)
{
	_cleanup_free_ char *bad_tag = tamper(PK_V3, 0);
	_cleanup_free_ char *bad_data = tamper(PK_V3, AES_GCM_TAG_LEN);
	_cleanup_free_ char *bad_iv = tamper_iv(PK_V3);

	check_private_key_rejected(bad_tag, key);
	check_private_key_rejected(bad_data, key);
	check_private_key_rejected(bad_iv, key);
	check_private_key_rejected(PK_V1, wrong_key);
	check_private_key_rejected(PK_V2, wrong_key);
	check_private_key_rejected(PK_V3, wrong_key);
}

static void check_private_key_roundtrip(enum cipher_aes_mode mode, char marker)
{
	unsigned char bytes[sizeof(pk_bytes)];
	struct private_key pk = { .key = bytes, .len = sizeof(bytes) };
	_cleanup_free_ char *encrypted = NULL;

	memcpy(bytes, pk_bytes, sizeof(bytes));
	encrypted = cipher_encrypt_private_key(&pk, key, mode);
	CHECK(encrypted[0] == marker);
	check_private_key(encrypted);
	check_private_key_rejected(encrypted, wrong_key);
}

static void test_private_key_roundtrip(void)
{
	check_private_key_roundtrip(CIPHER_AES_CBC, '!');
	check_private_key_roundtrip(CIPHER_AES_GCM, '#');
}

static struct account *add_account(struct blob *blob, const char *id,
				   const char *name, const char *group,
				   const char *username, const char *password,
				   const char *note)
{
	struct account *account = new_account();

	account->id = xstrdup(id);
	account->url = xstrdup("https://example.com/");
	account->name_encrypted = xstrdup(name);
	account->group_encrypted = xstrdup(group);
	account->username_encrypted = xstrdup(username);
	account->password_encrypted = xstrdup(password);
	account->note_encrypted = xstrdup(note);
	list_add_tail(&account->list, &blob->account_head);
	return account;
}

static struct account *find_account(struct blob *blob, const char *id)
{
	struct account *account;

	list_for_each_entry(account, &blob->account_head, list) {
		if (!strcmp(account->id, id))
			return account;
	}
	return NULL;
}

/* the guards exit instead of returning, so run them in a child */
static void call_require_decrypted(struct account *account)
{
	account_require_decrypted(account);
}

static void call_reencrypt(struct account *account)
{
	account_reencrypt(account, key, &flag_off);
}

static void check_exits(void (*guard)(struct account *), struct account *account,
			int expected_status, const char *expected_error)
{
	_cleanup_free_ char *error = NULL;
	int status = 0;
	pid_t pid;

	fflush(stdout);
	capture_stderr_begin();
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}
	if (!pid) {
		guard(account);
		_exit(0);
	}
	waitpid(pid, &status, 0);
	error = capture_stderr_end();

	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected_status);
	if (expected_error)
		CHECK(strstr(error, expected_error));
	else
		CHECK(!*error);
}

static void test_mixed_blob(void)
{
	struct feature_flag feature_flag = { 0 };
	struct blob blob = { .version = 1 };
	struct blob *parsed, *reparsed;
	struct account *account, *tmp;
	_cleanup_free_ char *bad_gcm = tamper(GCM, 0);
	_cleanup_free_ char *data = NULL;
	_cleanup_free_ char *data2 = NULL;
	_cleanup_free_ char *log = NULL;
	size_t len;

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "1", GCM, ECB_HASH, CBC, ECB, GCM_EMPTY);
	add_account(&blob, "2", CBC, ECB_BANG, GCM_AMBIGUOUS, bad_gcm, "");

	len = blob_write(&blob, key, &data, &feature_flag);
	list_for_each_entry_safe(account, tmp, &blob.account_head, list) {
		list_del(&account->list);
		account_free(account);
	}

	capture_stderr_begin();
	parsed = blob_parse((unsigned char *) data, len, key, NULL);
	log = capture_stderr_end();
	/* group is legacy ECB starting with '#': the tag fails but ECB recovers it, kept with a warning */
	CHECK(count_substr(log, GCM_FAILED ": account 2, field password") == 1);
	CHECK(count_substr(log, GCM_FAILED) == 1);
	CHECK(count_substr(log, ECB_FALLBACK ": account 1, field group") == 1);
	CHECK(count_substr(log, ECB_FALLBACK) == 1);
	CHECK(parsed != NULL);
	if (!parsed)
		return;

	account = find_account(parsed, "1");
	CHECK(account != NULL);
	if (account) {
		CHECK(str_eq(account->name, GCM_PTEXT));
		CHECK(str_eq(account->group, ECB_HASH_PTEXT));
		CHECK(str_eq(account->username, CBC_PTEXT));
		CHECK(str_eq(account->password, ECB_PTEXT));
		CHECK(str_eq(account->note, ""));
		CHECK(str_eq(account->url, "https://example.com/"));
		CHECK(str_eq(account->name_encrypted, GCM));
		CHECK(str_eq(account->group_encrypted, ECB_HASH));
		CHECK(str_eq(account->username_encrypted, CBC));
		CHECK(str_eq(account->password_encrypted, ECB));
		CHECK(str_eq(account->note_encrypted, GCM_EMPTY));
		/* ECB-recovered '#' group and an empty note are values, not failures */
		CHECK(account_undecrypted_field(account) == NULL);
		check_exits(call_require_decrypted, account, 0, NULL);
	}

	account = find_account(parsed, "2");
	CHECK(account != NULL);
	if (account) {
		CHECK(account->password_undecrypted);
		CHECK(!account->name_undecrypted && !account->group_undecrypted);
		CHECK(!account->username_undecrypted && !account->note_undecrypted);
		CHECK(str_eq(account_undecrypted_field(account), "password"));
		CHECK(str_eq(account->name, CBC_PTEXT));
		CHECK(str_eq(account->group, ECB_BANG_PTEXT));
		CHECK(str_eq(account->username, GCM_AMBIGUOUS_PTEXT));
		CHECK(str_eq(account->password, ""));
		CHECK(str_eq(account->name_encrypted, CBC));
		CHECK(str_eq(account->group_encrypted, ECB_BANG));
		CHECK(str_eq(account->username_encrypted, GCM_AMBIGUOUS));
		CHECK(str_eq(account->password_encrypted, bad_gcm));
	}

	len = blob_write(parsed, key, &data2, &feature_flag);
	free(log);
	capture_stderr_begin();
	reparsed = blob_parse((unsigned char *) data2, len, key, NULL);
	log = capture_stderr_end();
	CHECK(count_substr(log, GCM_FAILED) == 1);
	CHECK(reparsed != NULL);
	if (reparsed) {
		account = find_account(reparsed, "1");
		CHECK(account && str_eq(account->name_encrypted, GCM));
		account = find_account(reparsed, "2");
		CHECK(account && str_eq(account->password_encrypted, bad_gcm));
		blob_free(reparsed);
	}
	blob_free(parsed);
}

/* stderr of the last parse_written() */
static char *parse_log;

static struct blob *parse_written(struct blob *blob, const unsigned char *k)
{
	struct feature_flag feature_flag = { 0 };
	struct account *account, *tmp;
	struct blob *parsed;
	_cleanup_free_ char *data = NULL;
	size_t len = blob_write(blob, k, &data, &feature_flag);

	list_for_each_entry_safe(account, tmp, &blob->account_head, list) {
		list_del(&account->list);
		account_free(account);
	}
	capture_stderr_begin();
	parsed = blob_parse((unsigned char *) data, len, k, NULL);
	free(parse_log);
	parse_log = capture_stderr_end();
	return parsed;
}

static void setup_home(void)
{
	const char *tmp = getenv("TMPDIR");

	xasprintf(&home, "%s/lpass-unit-XXXXXX", tmp ? tmp : "/tmp");
	if (!mkdtemp(home)) {
		perror("mkdtemp");
		exit(1);
	}
	setenv("LPASS_HOME", home, 1);
}

static void teardown_home(void)
{
	_cleanup_free_ char *queue = config_path("upload-queue");
	struct dirent *entry;
	DIR *dir = opendir(queue);

	if (dir) {
		while ((entry = readdir(dir))) {
			_cleanup_free_ char *name = NULL;

			if (entry->d_name[0] == '.')
				continue;
			xasprintf(&name, "upload-queue/%s", entry->d_name);
			config_unlink(name);
		}
		closedir(dir);
	}
	rmdir(queue);
	config_unlink("lpass.log");
	rmdir(home);
	free(home);
}

static char *read_upload_entry(void)
{
	_cleanup_free_ char *queue = config_path("upload-queue");
	char *text = NULL;
	struct dirent *entry;
	DIR *dir = opendir(queue);

	if (!dir)
		return NULL;
	while (!text && (entry = readdir(dir))) {
		_cleanup_free_ char *name = NULL;

		if (entry->d_name[0] == '.')
			continue;
		xasprintf(&name, "upload-queue/%s", entry->d_name);
		text = config_read_encrypted_string(name, key);
		config_unlink(name);
	}
	closedir(dir);
	return text;
}

static char *upload_param(const char *entry, const char *name)
{
	_cleanup_free_ char *copy = xstrdup(entry);
	char *cursor = copy;
	char *param, *value;

	strsep(&cursor, "\n");
	while (cursor) {
		param = strsep(&cursor, "\n");
		value = cursor ? strsep(&cursor, "\n") : NULL;
		if (value && !strcmp(param, name))
			return xstrdup(value);
	}
	return NULL;
}

static void check_upload_param(const char *entry, const char *name, const char *expected)
{
	_cleanup_free_ char *value = upload_param(entry, name);

	if (!str_eq(value, expected))
		fprintf(stderr, "upload param '%s' mismatch\n", name);
	CHECK(str_eq(value, expected));
}

static void upload(struct session *session, struct account *account, struct blob *blob, char **entry)
{
	lastpass_update_account(BLOB_SYNC_NO, key, session, account, blob);
	*entry = read_upload_entry();
	CHECK(*entry != NULL);
}

static void test_ecb_hash_roundtrip(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed;
	struct session *session = session_new();
	struct account *account;
	_cleanup_free_ char *entry = NULL;
	_cleanup_free_ char *password = NULL;

	session->token = xstrdup("token");
	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "1", ECB_HASH, ECB_HASH, ECB_BANG, ECB_HASH, ECB_BANG);

	parsed = parse_written(&blob, key);
	/* legacy ECB '#' values fail the GCM tag, but the ECB fallback decrypts them: warned, not an error */
	CHECK(count_substr(parse_log, GCM_FAILED) == 0);
	CHECK(count_substr(parse_log, ECB_FALLBACK ": account 1, field name") == 1);
	CHECK(count_substr(parse_log, ECB_FALLBACK ": account 1, field group") == 1);
	CHECK(count_substr(parse_log, ECB_FALLBACK ": account 1, field password") == 1);
	CHECK(count_substr(parse_log, ECB_FALLBACK) == 3);
	account = parsed ? find_account(parsed, "1") : NULL;
	CHECK(account != NULL);
	if (!account)
		goto out;

	CHECK(str_eq(account->name, ECB_HASH_PTEXT));
	CHECK(str_eq(account->group, ECB_HASH_PTEXT));
	CHECK(str_eq(account->username, ECB_BANG_PTEXT));
	CHECK(str_eq(account->password, ECB_HASH_PTEXT));
	CHECK(str_eq(account->note, ECB_BANG_PTEXT));
	CHECK(str_eq(account->name_encrypted, ECB_HASH));
	CHECK(str_eq(account->group_encrypted, ECB_HASH));
	CHECK(str_eq(account->username_encrypted, ECB_BANG));
	CHECK(str_eq(account->password_encrypted, ECB_HASH));
	CHECK(str_eq(account->note_encrypted, ECB_BANG));
	/* recovered by the ECB fallback: not flagged, so the account stays rewritable */
	CHECK(account_undecrypted_field(account) == NULL);
	check_exits(call_require_decrypted, account, 0, NULL);

	account_set_username(account, xstrdup("edited-user"), key, &flag_off);
	CHECK(account->username_encrypted[0] == '!');

	upload(session, account, parsed, &entry);
	if (entry) {
		check_upload_param(entry, "name", ECB_HASH);
		check_upload_param(entry, "grouping", ECB_HASH);
		check_upload_param(entry, "password", ECB_HASH);
		check_upload_param(entry, "extra", ECB_BANG);
		password = upload_param(entry, "username");
		CHECK(str_eq(password, account->username_encrypted));
	}
out:
	blob_free(parsed);
	session_free(session);
}

static void test_ecb_hash_wrong_key(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed;
	struct account *account;

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "1", ECB_HASH, GCM, CBC, ECB, GCM_AMBIGUOUS);

	parsed = parse_written(&blob, wrong_key);
	CHECK(count_substr(parse_log, GCM_FAILED) == 3);
	account = parsed ? find_account(parsed, "1") : NULL;
	CHECK(account != NULL);
	if (account) {
		CHECK(str_eq(account->name, ""));
		CHECK(str_eq(account->group, ""));
		CHECK(str_eq(account->username, ""));
		CHECK(str_eq(account->password, ""));
		CHECK(str_eq(account->note, ""));
		/* GCM, CBC, ECB, ECB '#' and ambiguous values all end up flagged */
		CHECK(account->name_undecrypted);
		CHECK(account->group_undecrypted);
		CHECK(account->username_undecrypted);
		CHECK(account->password_undecrypted);
		CHECK(account->note_undecrypted);
		CHECK(str_eq(account_undecrypted_field(account), "name"));
		CHECK(str_eq(account->group_encrypted, GCM));
		CHECK(str_eq(account->username_encrypted, CBC));
		CHECK(str_eq(account->password_encrypted, ECB));
		CHECK(str_eq(account->note_encrypted, GCM_AMBIGUOUS));
		/* accepted risk: undecryptable ECB '#' value is labelled GCM */
		CHECK(account->name_encrypted[0] == '#');
		CHECK(!str_eq(account->name_encrypted, ECB_HASH));
	}
	blob_free(parsed);
}

static void check_encrypts_as_cbc(const char *ptext)
{
	_cleanup_free_ char *encrypted = encrypt_and_base64(ptext, key, CIPHER_AES_CBC);

	CHECK(encrypted[0] == '!');
	check_decrypts(encrypted, ptext);
}

static void test_write_path_flag_off(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed, *reparsed;
	struct session *session = session_new();
	struct account *account;
	_cleanup_free_ char *entry = NULL;
	_cleanup_free_ char *password = NULL;
	char text[64];
	size_t i;

	for (i = 1; i <= 48; i++) {
		memset(text, 'x', i);
		text[i] = '\0';
		check_encrypts_as_cbc(text);
	}

	session->token = xstrdup("token");
	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "5", GCM, GCM_EMPTY, GCM_AMBIGUOUS, GCM, GCM);

	parsed = parse_written(&blob, key);
	account = parsed ? find_account(parsed, "5") : NULL;
	CHECK(account != NULL);
	if (!account)
		goto out;

	CHECK(str_eq(account->name_encrypted, GCM));
	CHECK(str_eq(account->group_encrypted, GCM_EMPTY));
	CHECK(str_eq(account->username_encrypted, GCM_AMBIGUOUS));

	account_set_password(account, xstrdup("new-gcm-password"), key, &flag_off);
	CHECK(account->password_encrypted[0] == '!');
	check_decrypts(account->password_encrypted, "new-gcm-password");
	CHECK(str_eq(account->name_encrypted, GCM));
	CHECK(str_eq(account->group_encrypted, GCM_EMPTY));
	CHECK(str_eq(account->username_encrypted, GCM_AMBIGUOUS));
	CHECK(str_eq(account->note_encrypted, GCM));

	upload(session, account, parsed, &entry);
	if (entry) {
		check_upload_param(entry, "name", GCM);
		check_upload_param(entry, "grouping", GCM_EMPTY);
		check_upload_param(entry, "username", GCM_AMBIGUOUS);
		check_upload_param(entry, "extra", GCM);
		password = upload_param(entry, "password");
		CHECK(password && password[0] == '!');
		check_decrypts(password, "new-gcm-password");
	}

	reparsed = parse_written(parsed, key);
	blob_free(parsed);
	parsed = NULL;
	account = reparsed ? find_account(reparsed, "5") : NULL;
	CHECK(account != NULL);
	if (account) {
		CHECK(str_eq(account->password, "new-gcm-password"));
		CHECK(str_eq(account->name, GCM_PTEXT));
		CHECK(str_eq(account->name_encrypted, GCM));
		CHECK(account->password_encrypted[0] == '!');

		account_set_name(account, xstrdup("n"), key, &flag_off);
		account_set_group(account, xstrdup("g"), key, &flag_off);
		account_set_username(account, xstrdup("u"), key, &flag_off);
		account_set_password(account, xstrdup("p"), key, &flag_off);
		account_set_note(account, xstrdup("t"), key, &flag_off);
		CHECK(account->name_encrypted[0] == '!');
		CHECK(account->group_encrypted[0] == '!');
		CHECK(account->username_encrypted[0] == '!');
		CHECK(account->password_encrypted[0] == '!');
		CHECK(account->note_encrypted[0] == '!');
	}
	blob_free(reparsed);
out:
	blob_free(parsed);
	session_free(session);
}

static void check_encrypts_as(const char *ptext, enum cipher_aes_mode mode)
{
	_cleanup_free_ char *encrypted = encrypt_and_base64(ptext, key, mode);
	_cleanup_free_ unsigned char *raw = NULL;
	_cleanup_free_ char *wrong = NULL;
	size_t len;

	CHECK(encrypted[0] == (mode == CIPHER_AES_GCM ? CIPHER_MARKER_GCM : CIPHER_MARKER_CBC));
	check_decrypts(encrypted, ptext);
	check_raw_decrypts(encrypted, ptext, mode);
	if (mode != CIPHER_AES_GCM)
		return;

	len = cipher_unbase64(encrypted, &raw);
	CHECK(len == AES_GCM_MIN_LEN + strlen(ptext));
	/* the tag authenticates, so a wrong key never decrypts (CBC would pass padding 1/256) */
	wrong = cipher_aes_decrypt_base64_ex(encrypted, wrong_key, NULL);
	CHECK(wrong == NULL);
}

static void test_encrypt_roundtrip(void)
{
	const enum cipher_aes_mode modes[] = { CIPHER_AES_CBC, CIPHER_AES_GCM };
	_cleanup_free_ char *empty = encrypt_and_base64("", key, CIPHER_AES_GCM);
	char text[1001];
	size_t i, m;

	CHECK(str_eq(empty, ""));
	for (m = 0; m < ARRAY_SIZE(modes); m++) {
		/* covers lengths where GCM output is a multiple of 16, like ECB */
		for (i = 1; i <= 48; i++) {
			memset(text, 'x', i);
			text[i] = '\0';
			check_encrypts_as(text, modes[m]);
		}
		memset(text, 'y', 1000);
		text[1000] = '\0';
		check_encrypts_as(text, modes[m]);
		check_encrypts_as("p\xc3\xa4ssw\xc3\xb6rd-\xe2\x82\xac", modes[m]);
	}
}

static void test_gcm_iv_unique(void)
{
	_cleanup_free_ char *first = encrypt_and_base64("same plaintext", key, CIPHER_AES_GCM);
	_cleanup_free_ char *second = encrypt_and_base64("same plaintext", key, CIPHER_AES_GCM);
	_cleanup_free_ unsigned char *raw1 = NULL;
	_cleanup_free_ unsigned char *raw2 = NULL;
	unsigned char ivs[256][AES_GCM_IV_LEN];
	size_t len1 = cipher_unbase64(first, &raw1);
	size_t len2 = cipher_unbase64(second, &raw2);
	size_t i, j;

	CHECK(strcmp(first, second));
	CHECK(len1 == len2 && len1 > AES_GCM_MIN_LEN);
	if (len1 != len2 || len1 <= AES_GCM_MIN_LEN)
		return;
	CHECK(memcmp(raw1 + 1, raw2 + 1, AES_GCM_IV_LEN));
	CHECK(memcmp(raw1 + 1 + AES_GCM_IV_LEN, raw2 + 1 + AES_GCM_IV_LEN, len1 - 1 - AES_GCM_IV_LEN));

	for (i = 0; i < ARRAY_SIZE(ivs); i++) {
		_cleanup_free_ char *text = encrypt_and_base64("same plaintext", key, CIPHER_AES_GCM);
		_cleanup_free_ unsigned char *raw = NULL;

		CHECK(cipher_unbase64(text, &raw) == len1);
		memcpy(ivs[i], raw + 1, AES_GCM_IV_LEN);
		for (j = 0; j < i; j++)
			CHECK(memcmp(ivs[i], ivs[j], AES_GCM_IV_LEN));
	}
}

static void test_gcm_encrypt_tampered(void)
{
	_cleanup_free_ char *encrypted = encrypt_and_base64("tamper me", key, CIPHER_AES_GCM);
	_cleanup_free_ char *bad_tag = tamper(encrypted, 0);
	_cleanup_free_ char *bad_data = tamper(encrypted, AES_GCM_TAG_LEN);
	_cleanup_free_ char *bad_iv = tamper_iv(encrypted);
	bool failed;

	CHECK(cipher_aes_decrypt_base64_ex(bad_tag, key, &failed) == NULL);
	CHECK(failed);
	CHECK(cipher_aes_decrypt_base64_ex(bad_data, key, &failed) == NULL);
	CHECK(failed);
	CHECK(cipher_aes_decrypt_base64_ex(bad_iv, key, &failed) == NULL);
	CHECK(failed);
}

static void check_auth_failed_flag(const char *text, const char *expected, bool expected_failed)
{
	char *ptext;
	bool failed = !expected_failed;

	ptext = cipher_aes_decrypt_base64_ex(text, key, &failed);
	CHECK(failed == expected_failed);
	if (expected)
		CHECK(str_eq(ptext, expected));
	else
		CHECK(ptext == NULL);
	free(ptext);
}

static void test_gcm_auth_failed_flag(void)
{
	_cleanup_free_ char *bad_tag = tamper(GCM, 0);
	_cleanup_free_ unsigned char *raw = NULL;
	char *ptext;
	enum cipher_aes_mode mode;
	bool failed;
	size_t len;

	check_auth_failed_flag(GCM, GCM_PTEXT, false);
	check_auth_failed_flag(CBC, CBC_PTEXT, false);
	check_auth_failed_flag(ECB, ECB_PTEXT, false);
	check_auth_failed_flag(bad_tag, NULL, true);
	/* plain base64 has no marker: ECB only, its leading '#' is not a GCM header */
	check_auth_failed_flag(ECB_HASH, ECB_HASH_PTEXT, false);

	/* legacy ECB value starting with '#': decrypts through the fallback, tag still failed */
	len = cipher_unbase64(ECB_HASH, &raw);
	ptext = cipher_aes_decrypt_mode(raw, len, key, &mode, &failed);
	CHECK(str_eq(ptext, ECB_HASH_PTEXT));
	CHECK(mode == CIPHER_AES_ECB);
	CHECK(failed);
	free(ptext);

	/* ... but '!' is not GCM */
	free(raw);
	raw = NULL;
	len = cipher_unbase64(ECB_BANG, &raw);
	ptext = cipher_aes_decrypt_mode(raw, len, key, &mode, &failed);
	CHECK(str_eq(ptext, ECB_BANG_PTEXT));
	CHECK(!failed);
	free(ptext);
}

static void test_blob_reports_gcm_failure(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed;
	struct account *account;
	struct field *field;
	_cleanup_free_ char *bad_gcm = tamper(GCM, 0);
	_cleanup_free_ char *data = NULL;
	_cleanup_free_ char *log = NULL;
	struct account *tmp;
	size_t len;

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	account = add_account(&blob, "7", GCM, GCM_EMPTY, CBC, bad_gcm, GCM);
	field = new0(struct field, 1);
	/* field names are vault data, shared folder members can set them */
	field->name = xstrdup("pin\x1b[2J\nError: fake");
	field->type = xstrdup("text");
	field->value = xstrdup("");
	field->value_encrypted = xstrdup(bad_gcm);
	list_add_tail(&field->list, &account->field_head);

	len = blob_write(&blob, key, &data, &flag_off);
	list_for_each_entry_safe(account, tmp, &blob.account_head, list) {
		list_del(&account->list);
		account_free(account);
	}

	capture_stderr_begin();
	parsed = blob_parse((unsigned char *) data, len, key, NULL);
	log = capture_stderr_end();

	CHECK(parsed != NULL);
	CHECK(count_substr(log, GCM_FAILED) == 2);
	CHECK(strstr(log, GCM_FAILED ": account 7, field password") != NULL);
	CHECK(strstr(log, GCM_FAILED ": account 7, field pin") != NULL);
	CHECK(strchr(log, '\x1b') == NULL);
	CHECK(count_substr(log, "\n") == 2);
	/* never leak ciphertext or plaintext in the message */
	CHECK(strstr(log, bad_gcm) == NULL);
	if (!parsed)
		return;
	account = find_account(parsed, "7");
	CHECK(account != NULL);
	if (account) {
		/* the other fields of the vault still load */
		CHECK(str_eq(account->name, GCM_PTEXT));
		CHECK(str_eq(account->username, CBC_PTEXT));
		CHECK(str_eq(account->password, ""));
	}
	blob_free(parsed);
}

/* two bytes short: neither a CBC nor an ECB length, so no mode decrypts it and no tag is involved */
static char *truncate_cipher(const char *text, size_t drop)
{
	_cleanup_free_ unsigned char *raw = NULL;
	size_t len = cipher_unbase64(text, &raw);

	return cipher_base64(raw, len - drop);
}

static void test_blob_reports_other_decrypt_failure(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed;
	struct account *account, *tmp;
	_cleanup_free_ char *bad_cbc = truncate_cipher(CBC, 2);
	_cleanup_free_ char *data = NULL;
	_cleanup_free_ char *log = NULL;
	char *ptext, *empty;
	size_t len;

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "8", GCM, "", CBC, bad_cbc, "");
	len = blob_write(&blob, key, &data, &flag_off);
	list_for_each_entry_safe(account, tmp, &blob.account_head, list) {
		list_del(&account->list);
		account_free(account);
	}

	capture_stderr_begin();
	parsed = blob_parse((unsigned char *) data, len, key, NULL);
	log = capture_stderr_end();

	CHECK(parsed != NULL);
	/* an empty group and note are values, not failures */
	CHECK(strstr(log, "AES decryption failed: account 8, field password\n") != NULL);
	CHECK(count_substr(log, "\n") == 1);
	CHECK(strstr(log, GCM_FAILED) == NULL);
	if (parsed) {
		account = find_account(parsed, "8");
		CHECK(account != NULL);
		if (account) {
			CHECK(account->password_undecrypted);
			CHECK(str_eq(account->name, GCM_PTEXT));
			CHECK(str_eq(account->username, CBC_PTEXT));
		}
		blob_free(parsed);
	}

	free(log);
	capture_stderr_begin();
	ptext = cipher_aes_decrypt_base64_report(bad_cbc, key, "item %d", 1);
	empty = cipher_aes_decrypt_base64_report("", key, "item %d", 2);
	log = capture_stderr_end();
	CHECK(ptext == NULL && empty == NULL);
	CHECK(strstr(log, "AES decryption failed: item 1\n") != NULL);
	CHECK(strstr(log, "item 2") == NULL);
}

static struct account *add_url_account(struct blob *blob, const char *id, const char *url_encrypted)
{
	struct account *account = add_account(blob, id, CBC, "", "", "", "");

	if (url_encrypted)
		account->url_encrypted = xstrdup(url_encrypted);
	return account;
}

/* the binary URL item is hex or ciphertext: '#' must route to decryption like '!' */
static void test_blob_url_routing(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed;
	struct account *account, *tmp;
	_cleanup_free_ char *bad_gcm = tamper(GCM, 0);
	_cleanup_free_ char *data = NULL;
	_cleanup_free_ char *log = NULL;
	size_t len;

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_url_account(&blob, "1", GCM);
	add_url_account(&blob, "2", CBC);
	add_url_account(&blob, "3", NULL);
	add_url_account(&blob, "4", bad_gcm);
	account = add_url_account(&blob, "5", NULL);
	account_set_url(account, xstrdup("https://gcm-write.example.com/"), key, &flag_on_url);
	CHECK(account->url_encrypted && account->url_encrypted[0] == '#');

	len = blob_write(&blob, key, &data, &flag_off_url);
	list_for_each_entry_safe(account, tmp, &blob.account_head, list) {
		list_del(&account->list);
		account_free(account);
	}

	capture_stderr_begin();
	parsed = blob_parse((unsigned char *) data, len, key, NULL);
	log = capture_stderr_end();
	CHECK(count_substr(log, GCM_FAILED ": account 4, field url") == 1);
	CHECK(count_substr(log, "\n") == 1);
	CHECK(parsed != NULL);
	if (!parsed)
		return;

	account = find_account(parsed, "1");
	CHECK(account && str_eq(account->url, GCM_PTEXT) && str_eq(account->url_encrypted, GCM));
	CHECK(account && !account->url_undecrypted);
	account = find_account(parsed, "2");
	CHECK(account && str_eq(account->url, CBC_PTEXT) && str_eq(account->url_encrypted, CBC));
	account = find_account(parsed, "3");
	CHECK(account && str_eq(account->url, "https://example.com/"));
	account = find_account(parsed, "4");
	CHECK(account && str_eq(account->url, "") && account->url_undecrypted);
	CHECK(account && str_eq(account->url_encrypted, bad_gcm));
	account = find_account(parsed, "5");
	CHECK(account && str_eq(account->url, "https://gcm-write.example.com/"));
	CHECK(account && account->url_encrypted && account->url_encrypted[0] == '#');
	blob_free(parsed);
}

/* the formats lpass stores: PKCS#8 private key, SubjectPublicKeyInfo public key */
static void make_rsa_keys(struct private_key *private_key, struct public_key *public_key)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	EVP_PKEY *pkey = NULL;
	unsigned char *p;
	int len;

	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0 ||
	    !(p8inf = EVP_PKEY2PKCS8(pkey)))
		die("Could not generate a test RSA key.");

	len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len <= 0)
		die("Could not encode the test RSA private key.");
	private_key->len = len;
	private_key->key = p = xmalloc(len);
	i2d_PKCS8_PRIV_KEY_INFO(p8inf, &p);

	len = i2d_PUBKEY(pkey, NULL);
	if (len <= 0)
		die("Could not encode the test RSA public key.");
	public_key->len = len;
	public_key->key = p = xmalloc(len);
	i2d_PUBKEY(pkey, &p);

	PKCS8_PRIV_KEY_INFO_free(p8inf);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
}

static void append_item(struct buffer *buffer, const char *bytes)
{
	size_t len = strlen(bytes);
	unsigned char be32[4] = {
		(unsigned char) (len >> 24), (unsigned char) (len >> 16),
		(unsigned char) (len >> 8), (unsigned char) len,
	};

	buffer_append(buffer, be32, sizeof(be32));
	buffer_append(buffer, (void *) bytes, len);
}

/* SHAR chunk body as the server sends it: id, RSA-encrypted hex share key, encrypted name, readonly */
static struct share *make_share(const char *id, const unsigned char share_key[KDF_HASH_LEN],
				const char *name_encrypted, const struct public_key *public_key)
{
	struct share *share = new0(struct share, 1);
	struct buffer buffer;
	_cleanup_free_ char *hex_key = NULL;
	_cleanup_free_ char *hex_ciphertext = NULL;
	unsigned char ciphertext[4096];
	size_t len = sizeof(ciphertext);

	bytes_to_hex((unsigned char *) share_key, &hex_key, KDF_HASH_LEN);
	if (cipher_rsa_encrypt(hex_key, public_key, ciphertext, &len))
		die("Could not encrypt the test share key.");
	bytes_to_hex(ciphertext, &hex_ciphertext, len);

	buffer_init(&buffer);
	append_item(&buffer, id);
	append_item(&buffer, hex_ciphertext);
	append_item(&buffer, name_encrypted);
	append_item(&buffer, "0");
	share->chunk = buffer.bytes;
	share->chunk_len = buffer.len;
	return share;
}

static void test_failed_share_items_skipped(void)
{
	struct blob blob = { .version = 1 };
	struct private_key private_key;
	struct public_key public_key;
	unsigned char key_a[KDF_HASH_LEN], key_b[KDF_HASH_LEN];
	_cleanup_free_ char *name_a = NULL;
	_cleanup_free_ char *bad_name_a = NULL;
	_cleanup_free_ char *name_b = NULL;
	_cleanup_free_ char *item_a = NULL;
	_cleanup_free_ char *item_b = NULL;
	_cleanup_free_ char *data = NULL;
	_cleanup_free_ char *log = NULL;
	struct share *share_a, *share_b, *share;
	struct account *account, *tmp;
	struct field *field;
	struct blob *parsed;
	size_t len, n_shares = 0;

	make_rsa_keys(&private_key, &public_key);
	memset(key_a, 0xa5, sizeof(key_a));
	memset(key_b, 0x5a, sizeof(key_b));
	name_a = encrypt_and_base64("folder-a", key_a, CIPHER_AES_GCM);
	bad_name_a = tamper(name_a, 0);
	name_b = encrypt_and_base64("folder-b", key_b, CIPHER_AES_GCM);
	item_a = encrypt_and_base64("item-a", key_a, CIPHER_AES_GCM);
	item_b = encrypt_and_base64("item-b", key_b, CIPHER_AES_GCM);
	share_a = make_share("101", key_a, bad_name_a, &public_key);
	share_b = make_share("102", key_b, name_b, &public_key);

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "1", GCM, "", CBC, "", "");
	account = add_account(&blob, "2", item_a, "", item_a, item_a, "");
	account->share = share_a;
	field = new0(struct field, 1);
	field->name = xstrdup("pin");
	field->type = xstrdup("text");
	field->value = xstrdup("");
	field->value_encrypted = xstrdup(item_a);
	list_add_tail(&field->list, &account->field_head);
	account = add_account(&blob, "3", item_b, "", "", "", "");
	account->share = share_b;

	len = blob_write(&blob, key, &data, &flag_off);
	list_for_each_entry_safe(account, tmp, &blob.account_head, list) {
		list_del(&account->list);
		account_free(account);
	}
	share_free(share_a);
	share_free(share_b);

	capture_stderr_begin();
	parsed = blob_parse((unsigned char *) data, len, key, &private_key);
	log = capture_stderr_end();
	/* the share's name fails, then the share is skipped: nothing about its items */
	CHECK(count_substr(log, GCM_FAILED ": shared folder 101, field name") == 1);
	CHECK(count_substr(log, "Shared folder 101 could not be loaded, skipping its items.") == 1);
	CHECK(count_substr(log, "\n") == 2);
	CHECK(parsed != NULL);
	if (parsed) {
		CHECK(find_account(parsed, "2") == NULL);

		account = find_account(parsed, "1");
		CHECK(account && !account->share && str_eq(account->name, GCM_PTEXT));
		/* the skipped item's field must not attach to the previous account */
		CHECK(account && list_empty(&account->field_head));

		/* the next share loads again */
		account = find_account(parsed, "3");
		CHECK(account && account->share && str_eq(account->share->name, "folder-b"));
		CHECK(account && str_eq(account->name, "item-b"));

		list_for_each_entry(share, &parsed->share_head, list)
			n_shares++;
		CHECK(n_shares == 1);
		blob_free(parsed);
	}
	free(private_key.key);
	free(public_key.key);
}

static void test_private_key_reports_gcm_failure(void)
{
	_cleanup_free_ char *bad_tag = tamper(PK_V3, 0);
	_cleanup_free_ char *log = NULL;

	capture_stderr_begin();
	check_private_key_rejected(bad_tag, key);
	log = capture_stderr_end();
	CHECK(strstr(log, GCM_FAILED ": private key") != NULL);
}

static void test_error_msg_strips_terminal_controls(void)
{
	/* C0, DEL, C1 (CSI U+009B, NEL U+0085), bidi override U+202E, isolate U+2067, mark U+061C, U+2028 */
	const char *hostile = "a\x1b[2J\x7f|\xc2\x9b" "2J|\xc2\x85|\xe2\x80\xae|\xe2\x81\xa7|\xd8\x9c|\xe2\x80\xa8|z";
	/* legitimate UTF-8 sharing continuation bytes with the ranges above must survive */
	const char *benign = "caf\xc3\xa9 \xe2\x82\xac \xe2\x80\x94 \xc2\xa9 \xd8\xa7";
	_cleanup_free_ char *log = NULL;

	capture_stderr_begin();
	error_msg("%s", hostile);
	log = capture_stderr_end();
	CHECK(strchr(log, '\x1b') == NULL);
	CHECK(strchr(log, '\x7f') == NULL);
	CHECK(strstr(log, "\xc2\x9b") == NULL);
	CHECK(strstr(log, "\xc2\x85") == NULL);
	CHECK(strstr(log, "\xe2\x80\xae") == NULL);
	CHECK(strstr(log, "\xe2\x81\xa7") == NULL);
	CHECK(strstr(log, "\xd8\x9c") == NULL);
	CHECK(strstr(log, "\xe2\x80\xa8") == NULL);
	CHECK(strstr(log, "a?[2J?|??2J|??|???|???|??|???|z") != NULL);
	free(log);

	capture_stderr_begin();
	error_msg("%s", benign);
	log = capture_stderr_end();
	CHECK(strstr(log, benign) != NULL);
}

static void test_undecrypted_field_tracking(void)
{
	struct blob blob = { .version = 1 };
	struct feature_flag feature_flag = { 0 };
	struct blob *parsed;
	struct account *account;
	struct field *field;
	_cleanup_free_ char *bad_gcm = tamper(GCM, 0);

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	account = add_account(&blob, "1", GCM, GCM_EMPTY, CBC, ECB, GCM);
	field = new0(struct field, 1);
	field->name = xstrdup("pin");
	field->type = xstrdup("text");
	field->value = xstrdup("");
	field->value_encrypted = xstrdup(bad_gcm);
	list_add_tail(&field->list, &account->field_head);

	parsed = parse_written(&blob, key);
	account = parsed ? find_account(parsed, "1") : NULL;
	CHECK(account != NULL);
	if (!account)
		goto out;

	/* only the custom field failed: an empty group is a value, not a failure */
	CHECK(!account->name_undecrypted && !account->group_undecrypted);
	CHECK(!account->username_undecrypted && !account->password_undecrypted);
	CHECK(!account->note_undecrypted);
	field = list_first_entry(&account->field_head, struct field, list);
	CHECK(field->value_undecrypted);
	CHECK(str_eq(account_undecrypted_field(account), "pin"));

	/* writing the same empty value again leaves the stored ciphertext, so it stays unknown */
	field_set_value(account, field, xstrdup(""), key, &feature_flag);
	CHECK(field->value_undecrypted);
	CHECK(str_eq(field->value_encrypted, bad_gcm));

	/* a new value replaces it */
	field_set_value(account, field, xstrdup("1234"), key, &feature_flag);
	CHECK(!field->value_undecrypted);
	CHECK(account_undecrypted_field(account) == NULL);
	check_exits(call_require_decrypted, account, 0, NULL);
out:
	blob_free(parsed);
}

static void check_edited_fields_as(struct account *account, char marker)
{
	CHECK(account->name_encrypted[0] == marker);
	CHECK(account->group_encrypted[0] == marker);
	CHECK(account->username_encrypted[0] == marker);
	CHECK(account->password_encrypted[0] == marker);
	CHECK(account->note_encrypted[0] == marker);
	check_decrypts(account->name_encrypted, "n");
	check_decrypts(account->group_encrypted, "g");
	check_decrypts(account->username_encrypted, "u");
	check_decrypts(account->password_encrypted, "p");
	check_decrypts(account->note_encrypted, "t");
}

static void test_write_path_flag_on(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed, *reparsed;
	struct session *session = session_new();
	struct account *account;
	_cleanup_free_ char *entry = NULL;
	_cleanup_free_ char *password = NULL;

	session->token = xstrdup("token");
	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "5", CBC, GCM_EMPTY, GCM_AMBIGUOUS, ECB, GCM);

	parsed = parse_written(&blob, key);
	account = parsed ? find_account(parsed, "5") : NULL;
	CHECK(account != NULL);
	if (!account)
		goto out;

	/* an unchanged value is not re-encrypted, whatever the switch says */
	account_set_name(account, xstrdup(CBC_PTEXT), key, &flag_on);
	CHECK(str_eq(account->name_encrypted, CBC));

	account_set_password(account, xstrdup("new-gcm-password"), key, &flag_on);
	CHECK(account->password_encrypted[0] == '#');
	check_decrypts(account->password_encrypted, "new-gcm-password");
	CHECK(str_eq(account->name_encrypted, CBC));
	CHECK(str_eq(account->group_encrypted, GCM_EMPTY));
	CHECK(str_eq(account->username_encrypted, GCM_AMBIGUOUS));
	CHECK(str_eq(account->note_encrypted, GCM));

	upload(session, account, parsed, &entry);
	if (entry) {
		check_upload_param(entry, "name", CBC);
		check_upload_param(entry, "grouping", GCM_EMPTY);
		check_upload_param(entry, "username", GCM_AMBIGUOUS);
		check_upload_param(entry, "extra", GCM);
		password = upload_param(entry, "password");
		CHECK(password && password[0] == '#');
		check_decrypts(password, "new-gcm-password");
	}

	reparsed = parse_written(parsed, key);
	blob_free(parsed);
	parsed = NULL;
	account = reparsed ? find_account(reparsed, "5") : NULL;
	CHECK(account != NULL);
	if (account) {
		CHECK(str_eq(account->password, "new-gcm-password"));
		CHECK(account->password_encrypted[0] == '#');
		CHECK(str_eq(account->name_encrypted, CBC));

		account_set_name(account, xstrdup("n"), key, &flag_on);
		account_set_group(account, xstrdup("g"), key, &flag_on);
		account_set_username(account, xstrdup("u"), key, &flag_on);
		account_set_password(account, xstrdup("p"), key, &flag_on);
		account_set_note(account, xstrdup("t"), key, &flag_on);
		check_edited_fields_as(account, '#');
	}
	blob_free(reparsed);
out:
	blob_free(parsed);
	session_free(session);
}

static void test_write_mode_toggle(void)
{
	const struct feature_flag *flags[] = { &flag_on, &flag_off, &flag_on, &flag_off, &flag_on };
	struct blob blob = { .version = 1 };
	struct blob *parsed, *next;
	struct account *account;
	size_t round;

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "9", GCM, CBC, ECB, GCM_AMBIGUOUS, GCM_EMPTY);
	parsed = parse_written(&blob, key);

	for (round = 0; parsed && round < ARRAY_SIZE(flags); round++) {
		char value[32];
		char marker = flags[round]->aes_gcm_write_enabled ? '#' : '!';

		account = find_account(parsed, "9");
		CHECK(account != NULL);
		if (!account)
			break;
		snprintf(value, sizeof(value), "password-%zu", round);
		account_set_password(account, xstrdup(value), key, flags[round]);
		CHECK(account->password_encrypted[0] == marker);

		next = parse_written(parsed, key);
		blob_free(parsed);
		parsed = next;
		account = parsed ? find_account(parsed, "9") : NULL;
		CHECK(account != NULL);
		if (!account)
			break;
		/* every record stays readable in every state of the switch */
		CHECK(str_eq(account->password, value));
		CHECK(account->password_encrypted[0] == marker);
		CHECK(str_eq(account->name, GCM_PTEXT));
		CHECK(str_eq(account->group, CBC_PTEXT));
		CHECK(str_eq(account->username, ECB_PTEXT));
		CHECK(str_eq(account->note, ""));
		/* untouched fields keep their stored ciphertext */
		CHECK(str_eq(account->name_encrypted, GCM));
		CHECK(str_eq(account->group_encrypted, CBC));
		CHECK(str_eq(account->username_encrypted, ECB));
	}
	blob_free(parsed);
}

static void test_write_with_share_key(void)
{
	unsigned char share_key[KDF_HASH_LEN];
	struct share share = { 0 };
	struct account *account = new_account();
	_cleanup_free_ char *ptext = NULL;
	_cleanup_free_ char *wrong = NULL;
	size_t i;

	for (i = 0; i < sizeof(share_key); i++)
		share_key[i] = 0x80 + i;
	memcpy(share.key, share_key, sizeof(share_key));
	account->share = &share;

	account_set_name(account, xstrdup("shared-name"), key, &flag_on);
	CHECK(account->name_encrypted[0] == '#');
	ptext = cipher_aes_decrypt_base64_ex(account->name_encrypted, share_key, NULL);
	CHECK(str_eq(ptext, "shared-name"));
	wrong = cipher_aes_decrypt_base64_ex(account->name_encrypted, key, NULL);
	CHECK(wrong == NULL);

	account_set_name(account, xstrdup("shared-name-2"), key, &flag_off);
	CHECK(account->name_encrypted[0] == '!');
	free(ptext);
	ptext = cipher_aes_decrypt_base64_ex(account->name_encrypted, share_key, NULL);
	CHECK(str_eq(ptext, "shared-name-2"));

	account->share = NULL;
	account_free(account);
}

static void check_reencrypt(const struct feature_flag *initial, const struct feature_flag *target, char marker)
{
	struct account *account = new_account();
	struct field *field = new0(struct field, 1);

	account_set_name(account, xstrdup("name"), key, initial);
	account_set_group(account, xstrdup("group"), key, initial);
	account_set_url(account, xstrdup("https://example.com/"), key, initial);
	account_set_username(account, xstrdup("user"), key, initial);
	account_set_password(account, xstrdup("pass"), key, initial);
	account_set_note(account, xstrdup("note"), key, initial);
	field->name = xstrdup("pin");
	field->type = xstrdup("text");
	field_set_value(account, field, xstrdup("1234"), key, initial);
	list_add_tail(&field->list, &account->field_head);

	account_reencrypt(account, key, target);
	CHECK(account->name_encrypted[0] == marker);
	CHECK(account->group_encrypted[0] == marker);
	CHECK(account->url_encrypted[0] == marker);
	CHECK(account->username_encrypted[0] == marker);
	CHECK(account->password_encrypted[0] == marker);
	CHECK(account->note_encrypted[0] == marker);
	CHECK(field->value_encrypted[0] == marker);
	check_decrypts(account->name_encrypted, "name");
	check_decrypts(account->group_encrypted, "group");
	check_decrypts(account->url_encrypted, "https://example.com/");
	check_decrypts(account->username_encrypted, "user");
	check_decrypts(account->password_encrypted, "pass");
	check_decrypts(account->note_encrypted, "note");
	check_decrypts(field->value_encrypted, "1234");
	account_free(account);
}

static void test_reencrypt_follows_switch(void)
{
	check_reencrypt(&flag_off_url, &flag_on_url, '#');
	check_reencrypt(&flag_on_url, &flag_off_url, '!');
	check_reencrypt(&flag_on_url, &flag_on_url, '#');
}

static void check_login_flag(const char *attr, bool expected)
{
	_cleanup_free_ char *xml = NULL;
	struct session *session;

	xasprintf(&xml, "<response><ok uid=\"1\" sessionid=\"s\" token=\"t\"%s/></response>", attr);
	session = xml_ok_session(xml, key);
	CHECK(session != NULL);
	if (!session)
		return;
	CHECK(session->feature_flag.aes_gcm_write_enabled == expected);
	session_free(session);
}

static void test_flag_parse(void)
{
	check_login_flag(" enable_aes_gcm_write=\"1\"", true);
	/* the server omits the attribute when the switch is off */
	check_login_flag("", false);
	check_login_flag(" enable_aes_gcm_write=\"0\"", false);
	check_login_flag(" enable_aes_gcm_write=\"\"", false);
	check_login_flag(" enable_aes_gcm_write=\"true\"", false);
}

static void test_login_check_flag(void)
{
	struct session *session = session_new();

	session->feature_flag.aes_gcm_write_enabled = true;
	session->feature_flag.url_encryption_enabled = true;
	xml_login_check("<response><ok uid=\"1\" sessionid=\"s\" token=\"t\" accts_version=\"5\"/></response>", session);
	/* a server-side rollback must not leave the CLI writing GCM */
	CHECK(!session->feature_flag.aes_gcm_write_enabled);
	CHECK(session->feature_flag.url_encryption_enabled);

	xml_login_check("<response><ok uid=\"1\" sessionid=\"s\" token=\"t\" accts_version=\"6\" enable_aes_gcm_write=\"1\"/></response>", session);
	CHECK(session->feature_flag.aes_gcm_write_enabled);
	session_free(session);
}

static void test_flag_persist(void)
{
	struct feature_flag saved = { .aes_gcm_write_enabled = true };
	struct feature_flag loaded = { 0 };
	_cleanup_free_ char *path = config_path("session_ff_aes_gcm_write");

	feature_flag_save(&saved, key);
	feature_flag_load(&loaded, key);
	CHECK(loaded.aes_gcm_write_enabled);
	CHECK(!loaded.url_encryption_enabled);
	CHECK(access(path, F_OK) == 0);

	saved.aes_gcm_write_enabled = false;
	feature_flag_save(&saved, key);
	loaded.aes_gcm_write_enabled = true;
	feature_flag_load(&loaded, key);
	CHECK(!loaded.aes_gcm_write_enabled);

	saved.aes_gcm_write_enabled = true;
	feature_flag_save(&saved, key);
	feature_flag_cleanup();
	CHECK(access(path, F_OK) != 0);
	memset(&loaded, 0, sizeof(loaded));
	feature_flag_load(&loaded, key);
	CHECK(!loaded.aes_gcm_write_enabled);
}

static struct account *flagged_account(void)
{
	struct account *account = new_account();

	account->name_undecrypted = account->group_undecrypted = account->url_undecrypted = true;
	account->username_undecrypted = account->password_undecrypted = account->note_undecrypted = true;
	return account;
}

static int count_undecrypted(const struct account *account)
{
	return account->name_undecrypted + account->group_undecrypted + account->url_undecrypted +
	       account->username_undecrypted + account->password_undecrypted + account->note_undecrypted;
}

#define CHECK_SETTER_CLEARS(setter, flag, feature_flag) do { \
	struct account *__account = flagged_account(); \
	setter(__account, xstrdup("new-value"), key, feature_flag); \
	CHECK(!__account->flag); \
	CHECK(count_undecrypted(__account) == 5); \
	account_free(__account); \
} while (0)

static void test_setters_clear_undecrypted(void)
{
	CHECK_SETTER_CLEARS(account_set_name, name_undecrypted, &flag_off);
	CHECK_SETTER_CLEARS(account_set_group, group_undecrypted, &flag_off);
	CHECK_SETTER_CLEARS(account_set_username, username_undecrypted, &flag_off);
	CHECK_SETTER_CLEARS(account_set_password, password_undecrypted, &flag_off);
	CHECK_SETTER_CLEARS(account_set_note, note_undecrypted, &flag_off);
	/* url is stored plain or encrypted depending on the feature flag: separate code paths */
	CHECK_SETTER_CLEARS(account_set_url, url_undecrypted, &flag_off);
	CHECK_SETTER_CLEARS(account_set_url, url_undecrypted, &flag_off_url);
	CHECK_SETTER_CLEARS(account_set_password, password_undecrypted, &flag_on);
}

static void test_guards_refuse_undecrypted(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed;
	struct account *clean, *failed;
	_cleanup_free_ char *bad_gcm = tamper(GCM, 0);
	const char *refusal = "Refusing to rewrite account 2: field password could not be decrypted.";

	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "1", CBC, GCM_EMPTY, ECB, GCM, GCM_EMPTY);
	add_account(&blob, "2", CBC, GCM_EMPTY, ECB, bad_gcm, GCM_EMPTY);

	parsed = parse_written(&blob, key);
	clean = parsed ? find_account(parsed, "1") : NULL;
	failed = parsed ? find_account(parsed, "2") : NULL;
	CHECK(clean != NULL && failed != NULL);
	if (!clean || !failed)
		goto out;

	check_exits(call_require_decrypted, clean, 0, NULL);
	check_exits(call_reencrypt, clean, 0, NULL);
	check_exits(call_require_decrypted, failed, 1, refusal);
	check_exits(call_reencrypt, failed, 1, refusal);
out:
	blob_free(parsed);
}

static void test_set_url_drops_stale_ciphertext(void)
{
	_cleanup_free_ char *bad_gcm = tamper(GCM, 0);
	struct account *account = flagged_account();

	/* url encryption off: the url is stored plain, like on a new account */
	account->url = xstrdup("");
	account->url_encrypted = xstrdup(bad_gcm);
	account_set_url(account, xstrdup("https://new.example.com/"), key, &flag_off);
	CHECK(!account->url_undecrypted);
	CHECK(account->url_encrypted == NULL);
	CHECK(str_eq(account->url, "https://new.example.com/"));
	account_free(account);

	/* url encryption on: the new url is encrypted */
	account = flagged_account();
	account->url = xstrdup("");
	account->url_encrypted = xstrdup(bad_gcm);
	account_set_url(account, xstrdup("https://new.example.com/"), key, &flag_off_url);
	CHECK(!account->url_undecrypted);
	check_decrypts(account->url_encrypted, "https://new.example.com/");
	account_free(account);
}

static void test_field_undecrypted_names(void)
{
	struct account *account = flagged_account();

	CHECK(str_eq(account_field_undecrypted(account, "name"), "name"));
	CHECK(str_eq(account_field_undecrypted(account, "group"), "group"));
	CHECK(str_eq(account_field_undecrypted(account, "url"), "url"));
	CHECK(str_eq(account_field_undecrypted(account, "username"), "username"));
	CHECK(str_eq(account_field_undecrypted(account, "password"), "password"));
	CHECK(str_eq(account_field_undecrypted(account, "note"), "note"));
	/* export columns derived from a stored field */
	CHECK(str_eq(account_field_undecrypted(account, "extra"), "note"));
	CHECK(str_eq(account_field_undecrypted(account, "grouping"), "group"));
	CHECK(str_eq(account_field_undecrypted(account, "fullname"), "name"));
	/* not stored encrypted */
	CHECK(account_field_undecrypted(account, "id") == NULL);
	CHECK(account_field_undecrypted(account, "fav") == NULL);
	CHECK(account_field_undecrypted(account, "unknown") == NULL);

	account->name_undecrypted = false;
	CHECK(account_field_undecrypted(account, "name") == NULL);
	CHECK(str_eq(account_field_undecrypted(account, "fullname"), "group"));
	account->group_undecrypted = false;
	CHECK(account_field_undecrypted(account, "fullname") == NULL);
	CHECK(account_field_undecrypted(account, "grouping") == NULL);
	account_free(account);
}

static enum edit_choice edit_choice_under_test;
static struct session *edit_session;
static struct blob *edit_blob;

/* the refusals exit before any input is read, the edits that go ahead read a replacement */
static void call_edit(struct account *account)
{
	static const char replacement[] = "replacement\n";
	int fds[2];

	if (pipe(fds) || write(fds[1], replacement, sizeof(replacement) - 1) != sizeof(replacement) - 1)
		_exit(2);
	close(fds[1]);
	dup2(fds[0], STDIN_FILENO);
	edit_account(edit_session, edit_blob, BLOB_SYNC_NO, account, edit_choice_under_test,
		     NULL, true, key);
}

static void check_edit(struct account *account, enum edit_choice choice,
		       int expected_status, const char *expected_error)
{
	edit_choice_under_test = choice;
	check_exits(call_edit, account, expected_status, expected_error);
}

static void test_edit_refuses_unrepresentable_fields(void)
{
	struct blob blob = { .version = 1 };
	struct blob *parsed;
	struct session *session = session_new();
	struct account *account, *note;
	const char *url_refusal = "Refusing to rewrite account 1: field url could not be decrypted.";
	const char *name_refusal = "Refusing to rewrite account 1: field name could not be decrypted.";
	const char *note_refusal = "Refusing to rewrite account 2: field note could not be decrypted.";

	session->token = xstrdup("token");
	INIT_LIST_HEAD(&blob.account_head);
	INIT_LIST_HEAD(&blob.share_head);
	add_account(&blob, "1", CBC, GCM_EMPTY, ECB, GCM, GCM_EMPTY);
	add_account(&blob, "2", CBC, GCM_EMPTY, ECB, GCM, GCM_EMPTY);

	parsed = parse_written(&blob, key);
	account = parsed ? find_account(parsed, "1") : NULL;
	note = parsed ? find_account(parsed, "2") : NULL;
	CHECK(account != NULL && note != NULL);
	if (!account || !note)
		goto out;
	edit_session = session;
	edit_blob = parsed;

	/* the editor shows an undecrypted url empty, and an empty url saves as "http://" */
	account->url_undecrypted = true;
	free(account->url);
	account->url = xstrdup("");
	check_edit(account, EDIT_ANY, 1, url_refusal);
	check_edit(account, EDIT_URL, 1, url_refusal);
	/* edits of other fields never rewrite the url */
	check_edit(account, EDIT_PASSWORD, 0, NULL);

	/* an empty name would drop a group that did decrypt */
	account->url_undecrypted = false;
	free(account->url);
	account->url = xstrdup("https://example.com/");
	account->name_undecrypted = true;
	check_edit(account, EDIT_ANY, 1, name_refusal);
	check_edit(account, EDIT_NAME, 1, name_refusal);
	check_edit(account, EDIT_USERNAME, 0, NULL);

	/* a secure note whose note did not decrypt expands to nothing: no edit may go ahead */
	free(note->url);
	note->url = xstrdup("http://sn");
	free(note->note);
	note->note = xstrdup("");
	note->note_undecrypted = true;
	check_edit(note, EDIT_NOTES, 1, note_refusal);
	check_edit(note, EDIT_ANY, 1, note_refusal);
out:
	blob_free(parsed);
	session_free(session);
}

static void test_warning_msg_strips_terminal_controls(void)
{
	_cleanup_free_ char *log = NULL;

	capture_stderr_begin();
	warning_msg("account %s", "a\x1b[2J\xc2\x9b" "2J\xe2\x80\xae|z");
	log = capture_stderr_end();
	CHECK(strchr(log, '\x1b') == NULL);
	CHECK(strstr(log, "\xc2\x9b") == NULL);
	CHECK(strstr(log, "\xe2\x80\xae") == NULL);
	CHECK(strstr(log, "account a?[2J??2J???|z") != NULL);
}

int main(void)
{
	size_t i;

	setup_home();
	for (i = 0; i < sizeof(key); i++) {
		key[i] = i;
		wrong_key[i] = i + 1;
	}

	test_gcm_decrypt();
	test_legacy_decrypt();
	test_ecb_with_marker_byte();
	test_gcm_tampered();
	test_gcm_ambiguous_tampered();
	test_gcm_malformed_text();
	test_truncated_account_chunk();
	test_wrong_key();
	test_private_key();
	test_private_key_rejected();
	test_private_key_roundtrip();
	test_mixed_blob();
	test_ecb_hash_roundtrip();
	test_ecb_hash_wrong_key();
	test_write_path_flag_off();
	test_encrypt_roundtrip();
	test_gcm_iv_unique();
	test_gcm_encrypt_tampered();
	test_gcm_auth_failed_flag();
	test_blob_reports_gcm_failure();
	test_blob_reports_other_decrypt_failure();
	test_blob_url_routing();
	test_failed_share_items_skipped();
	test_private_key_reports_gcm_failure();
	test_error_msg_strips_terminal_controls();
	test_undecrypted_field_tracking();
	test_setters_clear_undecrypted();
	test_guards_refuse_undecrypted();
	test_set_url_drops_stale_ciphertext();
	test_field_undecrypted_names();
	test_edit_refuses_unrepresentable_fields();
	test_warning_msg_strips_terminal_controls();
	test_write_path_flag_on();
	test_write_mode_toggle();
	test_write_with_share_key();
	test_reencrypt_follows_switch();
	test_flag_parse();
	test_login_check_flag();
	test_flag_persist();
	free(parse_log);
	teardown_home();

	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("all cipher tests passed\n");
	return 0;
}
