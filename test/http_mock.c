/*
 * mock http server for testing
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../util.h"
#include "../blob.h"

#define TEST_USER "user@example.com"
#define TEST_PASS "123456"
#define TEST_FIDO_USER "fido@example.com"
#define TEST_UID "57747756"
#define TEST_FIDO_TOKEN "fido-test-token"
#define TEST_FIDO_CREDENTIAL "{\"id\":\"AQID\",\"extensions\":{},\"type\":\"public-key\",\"rawId\":\"AQID\",\"response\":{\"authenticatorData\":\"AQID\",\"clientDataJson\":\"AQID\",\"signature\":\"AQID\",\"userHandle\":null}}"

struct test_data
{
	char *username;
	char *password;
	char *uid;
	int iterations;
	unsigned char key[KDF_HASH_LEN];
	char login_hash[KDF_HEX_LEN];
	char fido_login_hash[KDF_HEX_LEN];
	struct blob blob;
};

struct test_data test_data;

static void init_test_data()
{
	static bool is_initialized;
	struct account *account;
	unsigned char *key;
	struct feature_flag *feature_flag = new0(struct feature_flag, 1);

	if (is_initialized)
		return;

	test_data.username = xstrdup(TEST_USER);
	test_data.password = xstrdup(TEST_PASS);
	test_data.uid = xstrdup(TEST_UID);
	test_data.iterations = 1000;

	kdf_login_key(test_data.username, test_data.password, test_data.iterations, test_data.login_hash);
	kdf_login_key(TEST_FIDO_USER, test_data.password, test_data.iterations,
		       test_data.fido_login_hash);
	kdf_decryption_key(test_data.username, test_data.password, test_data.iterations, test_data.key);

	test_data.blob.version = 1;
	test_data.blob.local_version = false;
	INIT_LIST_HEAD(&test_data.blob.account_head);
	INIT_LIST_HEAD(&test_data.blob.share_head);

	// existing server side accounts used by some tests
	key = test_data.key;
	account = new_account();
	account->id = xstrdup("0001");
	account_set_name(account, "test-account", key);
	account_set_group(account, "test-group", key);
	account_set_username(account, "xyz@example.com", key);
	account_set_password(account, "test-account-password", key);
	account_set_url(account, "https://test-url.example.com/", key, feature_flag);
	account_set_note(account, "", key);
	list_add_tail(&account->list, &test_data.blob.account_head);

	account = new_account();
	account->id = xstrdup("0002");
	account_set_name(account, "test-note", key);
	account_set_group(account, "test-group", key);
	account_set_username(account, xstrdup(""), key);
	account_set_password(account, xstrdup(""), key);
	account_set_url(account, "http://sn", key, feature_flag);
	account_set_note(account,
		"NoteType: Server\n"
		"Hostname: foo.example.com\n"
		"Username: test-note-user\n"
		"Password: test-note-password", key);
	list_add_tail(&account->list, &test_data.blob.account_head);

	account = new_account();
	account->id = xstrdup("0003");
	account_set_name(account, "test-reprompt-account", key);
	account_set_group(account, "test-group", key);
	account_set_username(account, "xyz@example.com", key);
	account_set_password(account, "test-account-password", key);
	account_set_url(account, "https://test-url.example.com/", key, feature_flag);
	account_set_note(account, "", key);
	account->pwprotect = true;
	list_add_tail(&account->list, &test_data.blob.account_head);

	account = new_account();
	account->id = xstrdup("0004");
	account_set_name(account, "test-reprompt-note", key);
	account_set_group(account, "test-group", key);
	account_set_username(account, xstrdup(""), key);
	account_set_password(account, xstrdup(""), key);
	account_set_url(account, "http://sn", key, feature_flag);
	account_set_note(account,
		"NoteType: Server\n"
		"Hostname: foo.example.com\n"
		"Username: test-note-user\n"
		"Password: test-note-password", key);
	account->pwprotect = true;
	list_add_tail(&account->list, &test_data.blob.account_head);

	/* AES-256-GCM fields written by another client */
	account = new_account();
	account->id = xstrdup("0005");
	account->name_encrypted = xstrdup("#EBAQEBAQEBAQEBAQ|TQxU3iO1cnw+UTY6w9G4QQRHTAE41EA2vMN68WHET6M=");
	account->group_encrypted = xstrdup("#ERERERERERERERER|XUB7m/yX/zchx2/l9quxrnWv5Lchzr9jWn8=");
	account->username_encrypted = xstrdup("#EhISEhISEhISEhIS|GU9542lNwLjS4hHOUUA3+iws7Ndlv6uRDvFcCbfbCw==");
	account->password_encrypted = xstrdup("#ExMTExMTExMTExMT|yjI68i+tqKXdCXKKuX9tugbMXeFJNh8fGiPlIHU7DNx8");
	account->note_encrypted = xstrdup("#FBQUFBQUFBQUFBQU|AUbZH6dQqa/UnkoJVaPDJfIoY+YElkJ4");
	account_set_url(account, "https://gcm.example.com/", key, feature_flag);
	list_add_tail(&account->list, &test_data.blob.account_head);

	is_initialized = true;
}

static char *get_param(char **argv, char *name)
{
	int i;
	for (i=0; argv[i]; i += 2) {
		if (!strcmp(argv[i], name))
			return argv[i + 1];
	}
	return NULL;
}

static bool param_is(char **argv, char *name, const char *expected)
{
	char *value = get_param(argv, name);
	return value && !strcmp(value, expected);
}

static bool param_has_value(char **argv, char *name)
{
	return get_param(argv, name) != NULL;
}

static char *getaccts(char **argv, size_t *len)
{
	UNUSED(argv);
	char *data = NULL;
	struct feature_flag *feature_flag = new0(struct feature_flag, 1);

	if (len)
		*len = blob_write(&test_data.blob, NULL, &data, feature_flag);
	return data;
}

static char *iterations(char **argv, size_t *len)
{
	UNUSED(argv);
	char *response = NULL;

	response = xultostr(test_data.iterations);
	if (len)
		*len = strlen(response);
	return response;
}

static char *show_website(char **argv, size_t *len)
{
	UNUSED(argv);
	if (len)
		*len = 0;
	return xstrdup("");
}

static char *login(char **argv, size_t *len)
{
	char *username = get_param(argv, "username");
	char *hash = get_param(argv, "hash");
	char *response;

	if (!strcmp(username, TEST_FIDO_USER)) {
		char *credential = get_param(argv, "fido2credential");
		if (strcmp(hash, test_data.fido_login_hash)) {
			response = xstrdup("<response><error message=\"invalid password\"/></response>");
		} else if (!credential) {
			response = xstrdup("<response><error message=\"MFA required\" "
				"cause=\"outofbandrequired\" outofbandname=\"LastPass Authenticator\" "
				"capabilities=\"yubikey,fido2\" primary=\"fido2\" "
				"fido2AuthToken=\"" TEST_FIDO_TOKEN "\" "
				"assertionOptions=\"{&quot;challenge&quot;:&quot;AQID&quot;,&quot;timeout&quot;:300000,&quot;rpId&quot;:&quot;lastpass.com&quot;,&quot;allowCredentials&quot;:[{&quot;type&quot;:&quot;public-key&quot;,&quot;id&quot;:&quot;AQID&quot;}],&quot;userVerification&quot;:&quot;preferred&quot;}\"/>"
				"</response>");
		} else if (strcmp(credential, TEST_FIDO_CREDENTIAL) ||
			   !param_is(argv, "provider", "lastpassauth") ||
			   !param_is(argv, "otp", "") ||
			   !param_is(argv, "outofbandrequest", "1") ||
			   !param_is(argv, "outofbandretry", "0") ||
			   !param_is(argv, "outofbandretryid", TEST_FIDO_TOKEN) ||
			   !param_is(argv, "voicecall", "0") ||
			   !param_has_value(argv, "uuid")) {
			response = xstrdup("<response><error message=\"invalid FIDO request\" "
				"cause=\"fido2failed\"/></response>");
		} else {
			response = xstrdup("<response><ok uid=\"" TEST_UID "\" "
				"sessionid=\"1234\" token=\"abcd\"/></response>");
		}
	} else if (strcmp(username, test_data.username) ||
		   strcmp(hash, test_data.login_hash)) {
		response = xstrdup("<response>"
			"<error message=\"invalid password\"/>"
			"</response>");
	} else {
		response = xstrdup("<response>"
			"<ok "
			"uid=\"" TEST_UID "\" "
			"sessionid=\"1234\" "
			"token=\"abcd\"/>"
			"</response>");
	}
	if (len)
		*len = strlen(response);
	return response;
}

static char *login_check(char **argv, size_t *len)
{
	UNUSED(argv);
	char *response = xstrdup("<response>"
			"<ok "
			"uid=\"" TEST_UID "\" "
			"sessionid=\"1234\" "
			"token=\"abcd\" "
			"accts_version=\"123\"/>"
			"</response>");
	if (len)
		*len = strlen(response);
	return response;
}

struct page_entry {
	char *name;
	char *(*fn)(char **, size_t *);
};

#define PAGE(x) { .name = #x ".php", .fn = x }
struct page_entry page_table[] = {
	PAGE(getaccts),
	PAGE(iterations),
	PAGE(login),
	PAGE(login_check),
	PAGE(show_website),
};

struct session;

/*
 * This implements a mock server for lpass for unit testing the client,
 * overriding the function of the same name from http.c.
 */
char *http_post_lastpass_v_noexit(const char *server, const char *page,
                                  const struct session *session,
                                  size_t *final_len, char **argv,
                                  int *curl_ret, long *http_code)
{
	unsigned int i;
	UNUSED(server);
	UNUSED(session);

	init_test_data();

	*curl_ret = 0;
	*http_code = 200;

	for (i = 0; i < ARRAY_SIZE(page_table); i++) {
		if (!strcmp(page, page_table[i].name)) {
			return page_table[i].fn(argv, final_len);
		}
	}
	fprintf(stderr, "unhandled page: %s\n", page);
	char *response = xstrdup("<response><error message=\"unimplemented\"/></response>");
	if (final_len)
		*final_len = strlen(response);
	return response;
}
