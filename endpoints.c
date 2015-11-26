/*
 * https endpoints for LastPass services
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
#include "endpoints.h"
#include "http.h"
#include "version.h"
#include "xml.h"
#include "config.h"
#include "util.h"
#include "upload-queue.h"
#include <string.h>
#include <errno.h>
#include <curl/curl.h>

unsigned int lastpass_iterations(const char *username)
{
	_cleanup_free_ char *reply = NULL;
	_cleanup_free_ char *user_lower = NULL;

	user_lower = xstrlower(username);
	reply = http_post_lastpass("iterations.php", NULL, NULL, "email", user_lower, NULL);

	if (!reply)
		return 0;

	return strtoul(reply, NULL, 10);
}

void lastpass_logout(const struct session *session)
{
	free(http_post_lastpass("logout.php", session->sessionid, NULL, "method", "cli", "noredirect", "1", NULL));
}

struct blob *lastpass_get_blob(const struct session *session, const unsigned char key[KDF_HASH_LEN])
{
	size_t len;

	_cleanup_free_ char *blob = http_post_lastpass("getaccts.php", session->sessionid, &len, "mobile", "1", "requestsrc", "cli", "hasplugin", LASTPASS_CLI_VERSION, NULL);
	if (!blob || !len)
		return NULL;
	config_write_encrypted_buffer("blob", blob, len, key);
	return blob_parse((unsigned char *) blob, len, key, &session->private_key);
}

void lastpass_remove_account(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const struct account *account, struct blob *blob)
{
	++blob->version;
	if (account->share)
		upload_queue_enqueue(sync, key, session, "show_website.php", "extjs", "1", "token", session->token, "delete", "1", "aid", account->id, "sharedfolderid", account->share->id, NULL);
	else
		upload_queue_enqueue(sync, key, session, "show_website.php", "extjs", "1", "token", session->token, "delete", "1", "aid", account->id, NULL);
}

static char *stringify_field(const struct field *field)
{
	char *str, *name, *type, *value, *intermediate;
	CURL *curl;

	curl = curl_easy_init();
	if (!curl)
		return xstrdup("");

	name = curl_easy_escape(curl, field->name, 0);
	type = curl_easy_escape(curl, field->type, 0);
	if (field->value_encrypted)
		value = curl_easy_escape(curl, field->value_encrypted, 0);
	else if (!strcmp(field->type, "checkbox") || !strcmp(field->type, "radio")) {
		xasprintf(&intermediate, "%s-%c", field->value, field->checked ? '1' : '0');
		value = curl_easy_escape(curl, intermediate, 0);
		free(intermediate);
	} else
		value = curl_easy_escape(curl, field->value, 0);

	xasprintf(&str, "0\t%s\t%s\t%s\n", name, value, type);

	curl_free(name);
	curl_free(type);
	curl_free(value);
	curl_easy_cleanup(curl);

	return str;
}

static char *stringify_fields(const struct list_head *field_head)
{
	char *field_str, *fields = NULL;
	struct field *field;

	list_for_each_entry(field, field_head, list) {
		field_str = stringify_field(field);
		xstrappend(&fields, field_str);
		free(field_str);
	}
	if (fields)
		xstrappend(&fields, "0\taction\t\taction\n0\tmethod\t\tmethod\n");
	else
		fields = xstrdup("");

	field_str = NULL;
	bytes_to_hex((unsigned char *) fields, &field_str, strlen(fields));
	free(fields);

	return field_str;
}

void lastpass_update_account(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const struct account *account, struct blob *blob)
{
	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *fields = NULL;

	bytes_to_hex((unsigned char *) account->url, &url, strlen(account->url));
	fields = stringify_fields(&account->field_head);

	++blob->version;

	if (account->share)
		upload_queue_enqueue(sync, key, session, "show_website.php", "extjs", "1",
				"token", session->token, "aid", account->id,
				"name", account->name_encrypted, "grouping", account->group_encrypted,
				"url", url, "username", account->username_encrypted,
				"password", account->password_encrypted, /* "data", fields,     Removing until server-side catches up. */
				"pwprotect", account->pwprotect ? "on" : "off",
				"extra", account->note_encrypted, "sharedfolderid", account->share->id, NULL);
	else
		upload_queue_enqueue(sync, key, session, "show_website.php", "extjs", "1",
				"token", session->token, "aid", account->id,
				"name", account->name_encrypted, "grouping", account->group_encrypted,
				"url", url, "username", account->username_encrypted,
				"password", account->password_encrypted, /* "data", fields,     Removing until server-side catches up. */
				"pwprotect", account->pwprotect ? "on" : "off",
				"extra", account->note_encrypted, NULL);
}

unsigned long long lastpass_get_blob_version(struct session *session, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *reply = NULL;
	unsigned long long version;

	reply = http_post_lastpass("login_check.php", session->sessionid, NULL, "method", "cli", NULL);
	if (!reply)
		return 0;
	version = xml_login_check(reply, session);
	if (version)
		session_save(session, key);
	return version;
}

void lastpass_log_access(enum blobsync sync, const struct session *session, unsigned const char key[KDF_HASH_LEN], const struct account *account)
{
	if (!strcmp(account->id, "0"))
		return;
	if (!account->share)
		upload_queue_enqueue(sync, key, session, "loglogin.php", "id", account->id, "method", "cli", NULL);
	else
		upload_queue_enqueue(sync, key, session, "loglogin.php", "id", account->id, "method", "cli", "sharedfolderid", account->share->id, NULL);
}


int lastpass_pwchange_start(const struct session *session, const char *username, const char hash[KDF_HEX_LEN], struct pwchange_info *info)
{
	_cleanup_free_ char *reply = NULL;

	reply = http_post_lastpass("lastpass/api.php", session->sessionid, NULL,
				   "cmd", "getacctschangepw",
				   "username", username,
				   "hash", hash,
				   "changepw", "1",
				   "changepw2", "1",
				   "includersaprivatekeyenc", "1",
				   "changeun", "",
				   "resetrsakeys", "0",
				   "includeendmarker", "1", NULL);
	if (!reply)
		return -ENOENT;

	return xml_parse_pwchange(reply, info);
}

int lastpass_pwchange_complete(const struct session *session,
			       const char *username,
			       const char *enc_username,
			       const char new_hash[KDF_HEX_LEN],
			       int new_iterations,
			       struct pwchange_info *info)
{
	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	struct pwchange_field *field;
	struct pwchange_su_key *su_key;
	_cleanup_free_ char *iterations_str = xultostr(new_iterations);
	_cleanup_free_ char *sukeycnt_str = NULL;
	_cleanup_free_ char *reencrypt_string = NULL;
	_cleanup_free_ char *reply = NULL;
	size_t len;
	int su_key_ind;
	char suuid_str[30] = {0};
	char sukey_str[30] = {0};
	unsigned int i;

	/* build reencrypt string from change pw info */
	len = strlen(info->reencrypt_id) + 1;
	list_for_each_entry(field, &info->fields, list) {
		len += strlen(field->old_ctext) + strlen(field->new_ctext) +
		       1 /* ':' */ + 1 /* '\n' */;
	}
	reencrypt_string = xcalloc(len + 1, 1);
	strlcat(reencrypt_string, info->reencrypt_id, len);
	strlcat(reencrypt_string, "\n", len);

	list_for_each_entry(field, &info->fields, list) {
		strlcat(reencrypt_string, field->old_ctext, len);
		strlcat(reencrypt_string, ":", len);
		strlcat(reencrypt_string, field->new_ctext, len);
		strlcat(reencrypt_string, "\n", len);
	}

	http_post_add_params(&params,
		"cmd", "updatepassword",
		"pwupdate", "1",
		"email", username,
		"token", info->token,
		"reencrypt", reencrypt_string,
		"newprivatekeyenc", info->new_privkey_encrypted,
		"newuserkeyhexhash", info->new_key_hash,
		"newprivatekeyenchexhash", info->new_privkey_hash,
		"newpasswordhash", new_hash,
		"key_iterations", iterations_str,
		"encrypted_username", enc_username,
		"origusername", username,
		NULL);

	su_key_ind = 0;
	list_for_each_entry(su_key, &info->su_keys, list) {
		snprintf(suuid_str, sizeof(suuid_str), "suuid%d", su_key_ind);
		snprintf(sukey_str, sizeof(sukey_str), "sukey%d", su_key_ind);
		http_post_add_params(&params,
				     xstrdup(suuid_str), su_key->uid,
				     xstrdup(sukey_str), su_key->new_enc_key,
				     NULL);
		su_key_ind++;
	}
	sukeycnt_str = xultostr(su_key_ind);
	http_post_add_params(&params, xstrdup("sukeycnt"), sukeycnt_str, NULL);

	reply = http_post_lastpass_param_set("lastpass/api.php",
					     session->sessionid, NULL,
					     &params);

	for (i=0; i < params.n_alloced && params.argv[i]; i++) {
		if (starts_with(params.argv[i], "sukey") ||
		    starts_with(params.argv[i], "suuid")) {
			free(params.argv[i]);
		}
	}

	if (!reply)
		return -EINVAL;

	if (!strstr(reply, "pwchangeok"))
		return -EINVAL;

	return 0;
}
