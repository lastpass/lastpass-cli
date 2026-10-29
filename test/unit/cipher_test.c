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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../blob.h"
#include "../../cipher.h"
#include "../../config.h"
#include "../../endpoints.h"
#include "../../feature-flag.h"
#include "../../session.h"
#include "../../util.h"

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

static void check_decrypts(const char *text, const char *expected)
{
	_cleanup_free_ char *ptext = cipher_aes_decrypt_base64(text, key);

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
	ptext = cipher_aes_decrypt_mode(raw, len, key, &mode);
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
	CHECK(cipher_aes_decrypt_base64(bad_tag, key) == NULL);
	CHECK(cipher_aes_decrypt_base64(bad_data, key) == NULL);
	CHECK(cipher_aes_decrypt_base64(bad_iv, key) == NULL);

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
	};
	unsigned char *raw = NULL;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(malformed); i++) {
		CHECK(cipher_unbase64(malformed[i], &raw) == 0);
		CHECK(cipher_aes_decrypt_base64(malformed[i], key) == NULL);
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
	CHECK(cipher_aes_decrypt_base64(bad, key) == NULL);
	ptext = cipher_aes_decrypt_mode(raw, len, key, &mode);
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
	_cleanup_free_ char *ptext = cipher_aes_decrypt_base64(text, wrong_key);
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

static void test_private_key_roundtrip(void)
{
	unsigned char bytes[sizeof(pk_bytes)];
	struct private_key pk = { .key = bytes, .len = sizeof(bytes) };
	_cleanup_free_ char *encrypted = NULL;

	memcpy(bytes, pk_bytes, sizeof(bytes));
	encrypted = cipher_encrypt_private_key(&pk, key);
	CHECK(encrypted[0] == '!');
	check_private_key(encrypted);
	check_private_key_rejected(encrypted, wrong_key);
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

static void test_mixed_blob(void)
{
	struct feature_flag feature_flag = { 0 };
	struct blob blob = { .version = 1 };
	struct blob *parsed, *reparsed;
	struct account *account, *tmp;
	_cleanup_free_ char *bad_gcm = tamper(GCM, 0);
	_cleanup_free_ char *data = NULL;
	_cleanup_free_ char *data2 = NULL;
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

	parsed = blob_parse((unsigned char *) data, len, key, NULL);
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
	}

	account = find_account(parsed, "2");
	CHECK(account != NULL);
	if (account) {
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
	reparsed = blob_parse((unsigned char *) data2, len, key, NULL);
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

static struct blob *parse_written(struct blob *blob, const unsigned char *k)
{
	struct feature_flag feature_flag = { 0 };
	struct account *account, *tmp;
	_cleanup_free_ char *data = NULL;
	size_t len = blob_write(blob, k, &data, &feature_flag);

	list_for_each_entry_safe(account, tmp, &blob->account_head, list) {
		list_del(&account->list);
		account_free(account);
	}
	return blob_parse((unsigned char *) data, len, k, NULL);
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

	account_set_username(account, xstrdup("edited-user"), key);
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
	account = parsed ? find_account(parsed, "1") : NULL;
	CHECK(account != NULL);
	if (account) {
		CHECK(str_eq(account->name, ""));
		CHECK(str_eq(account->group, ""));
		CHECK(str_eq(account->username, ""));
		CHECK(str_eq(account->password, ""));
		CHECK(str_eq(account->note, ""));
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
	_cleanup_free_ char *encrypted = encrypt_and_base64(ptext, key);

	CHECK(encrypted[0] == '!');
	check_decrypts(encrypted, ptext);
}

static void test_write_path_never_gcm(void)
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

	account_set_password(account, xstrdup("new-gcm-password"), key);
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

		account_set_name(account, xstrdup("n"), key);
		account_set_group(account, xstrdup("g"), key);
		account_set_username(account, xstrdup("u"), key);
		account_set_password(account, xstrdup("p"), key);
		account_set_note(account, xstrdup("t"), key);
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
	test_write_path_never_gcm();
	teardown_home();

	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("all cipher tests passed\n");
	return 0;
}
