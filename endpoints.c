/*
 * https endpoints for LastPass services
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
	free(http_post_lastpass("logout.php", session, NULL, "method", "cli", "noredirect", "1", "token", session->token, NULL));
}

struct blob *lastpass_get_blob(const struct session *session, const unsigned char key[KDF_HASH_LEN])
{
	size_t len;

	_cleanup_free_ char *blob = http_post_lastpass("getaccts.php", session, &len, "mobile", "1", "requestsrc", "cli", "hasplugin", LASTPASS_CLI_VERSION, NULL);
	if (!blob || !len)
		return NULL;
	config_write_encrypted_buffer("blob", blob, len, key);
	return blob_parse((unsigned char *) blob, len, key, &session->private_key);
}

void lastpass_remove_account(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const struct account *account, struct blob *blob)
{
	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	http_post_add_params(&params, "extjs", "1", "token", session->token, "delete", "1", "aid", account->id, NULL);

	if (account->share)
		http_post_add_params(&params, "sharedfolderid", account->share->id, NULL);

	++blob->version;
	upload_queue_enqueue(sync, key, session, "show_website.php", &params);
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

static void add_app_fields(const struct account *account,
			   struct http_param_set *params)
{
	int index = 0;
	struct field *field;

	list_for_each_entry(field, &account->field_head, list) {
		char *id_name, *type_name, *value_name;

		xasprintf(&id_name, "fieldid%d", index);
		xasprintf(&type_name, "fieldtype%d", index);
		xasprintf(&value_name, "fieldvalue%d", index);

		http_post_add_params(params,
				     id_name, field->name,
				     type_name, field->type,
				     value_name, field->value_encrypted,
				     NULL);
		index++;
	}
}

void lastpass_update_account(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const struct account *account, struct blob *blob)
{
	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *fields = NULL;

	bytes_to_hex((unsigned char *) account->url, &url, strlen(account->url));
	fields = stringify_fields(&account->field_head);

	++blob->version;

	http_post_add_params(&params,
			     "extjs", "1",
			     "token", session->token,
			     "method", "cli",
			     "name", account->name_encrypted,
			     "grouping", account->group_encrypted,
			     "pwprotect", account->pwprotect ? "on" : "off",
			     NULL);

	if (account->share) {
		http_post_add_params(&params,
				     "sharedfolderid", account->share->id,
				     NULL);
	}
	if (account->is_app) {
		struct app *app = account_to_app(account);

		http_post_add_params(&params,
				     "ajax", "1",
				     "cmd", "updatelpaa",
				     "appname", app->appname,
				     NULL);
		add_app_fields(account, &params);
		if (strcmp(account->id, "0"))
			http_post_add_params(&params, "appaid", account->id, NULL);

		upload_queue_enqueue(sync, key, session, "addapp.php", &params);
		goto out_free_params;
	}
	http_post_add_params(&params,
			     "aid", account->id,
			     "url", url,
			     "username", account->username_encrypted,
			     "password", account->password_encrypted,
			     "extra", account->note_encrypted,
			     NULL);

	if (strlen(fields)) {
		http_post_add_params(&params,
				     "save_all", "1",
				     "data", fields,
				     NULL);
	}
	upload_queue_enqueue(sync, key, session, "show_website.php", &params);

out_free_params:
	free(params.argv);
}

unsigned long long lastpass_get_blob_version(struct session *session, unsigned const char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *reply = NULL;
	unsigned long long version;

	reply = http_post_lastpass("login_check.php", session, NULL, "method", "cli", NULL);
	if (!reply)
		return 0;
	version = xml_login_check(reply, session);
	if (version)
		session_save(session, key);
	return version;
}

void lastpass_log_access(enum blobsync sync, const struct session *session, unsigned const char key[KDF_HASH_LEN], const struct account *account)
{
	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	if (!strcmp(account->id, "0"))
		return;

	http_post_add_params(&params, "id", account->id, "method", "cli", NULL);

	if (account->share)
		http_post_add_params(&params, "sharedfolderid", account->share->id, NULL);

	upload_queue_enqueue(sync, key, session, "loglogin.php", &params);

	free(params.argv);
}


int lastpass_pwchange_start(const struct session *session, const char *username, const char hash[KDF_HEX_LEN], struct pwchange_info *info)
{
	_cleanup_free_ char *reply = NULL;

	reply = http_post_lastpass("lastpass/api.php", session, NULL,
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
					     session, NULL,
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

/*
 * Upload a set of accounts, used for import.
 */
int lastpass_upload(const struct session *session,
		    struct list_head *accounts)
{
	_cleanup_free_ char *reply = NULL;
	struct account *account;
	int index;
	unsigned int i;

	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	if (list_empty(accounts))
		return 0;

	http_post_add_params(&params,
			     "token", session->token,
			     "cmd", "uploadaccounts",
			     NULL);

	index = 0;
	list_for_each_entry(account, accounts, list) {
		char *name_param, *grouping_param;
		char *url_param, *username_param, *password_param;
		char *fav_param, *extra_param;
		char *url = NULL;
		bytes_to_hex((unsigned char *) account->url, &url,
			     strlen(account->url));

		xasprintf(&name_param, "name%d", index);
		xasprintf(&grouping_param, "grouping%d", index);
		xasprintf(&url_param, "url%d", index);
		xasprintf(&username_param, "username%d", index);
		xasprintf(&password_param, "password%d", index);
		xasprintf(&fav_param, "fav%d", index);
		xasprintf(&extra_param, "extra%d", index);

		http_post_add_params(&params,
				     name_param, account->name_encrypted,
				     grouping_param, account->group_encrypted,
				     url_param, url,
				     username_param, account->username_encrypted,
				     password_param, account->password_encrypted,
				     fav_param, account->fav ? "1" : "0",
				     extra_param, account->note_encrypted,
				     NULL);
		index++;
	}

	reply = http_post_lastpass_param_set("lastpass/api.php",
					     session, NULL,
					     &params);

	for (i=0; i < params.n_alloced && params.argv[i]; i++) {
		if (starts_with(params.argv[i], "name") ||
		    starts_with(params.argv[i], "grouping") ||
		    starts_with(params.argv[i], "username") ||
		    starts_with(params.argv[i], "password") ||
		    starts_with(params.argv[i], "fav") ||
		    starts_with(params.argv[i], "extra")) {
			free(params.argv[i]);
		}
		else if (starts_with(params.argv[i], "url")) {
			free(params.argv[i]);
			if (i < params.n_alloced) {
				free(params.argv[i+1]);
				i++;
			}
		}
	}

	free(params.argv);

	if (!reply)
		return -EINVAL;

	return xml_api_err(reply);
}

/*
 * Get the attachment for a given attachment id.  The crypttext is returned
 * and should be decrypted with account->attachkey.  The pointer returned
 * in *result should be freed by the caller.
 */
int lastpass_load_attachment(const struct session *session,
			     const char *shareid,
			     struct attach *attach,
			     char **result)
{
	char *reply = NULL;
	char *p;

	*result = NULL;

	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	http_post_add_params(&params,
			     "token", session->token,
			     "getattach", attach->storagekey,
			     NULL);

	if (shareid) {
		http_post_add_params(&params,
				     "sharedfolderid", shareid,
				     NULL);
	}

	reply = http_post_lastpass_param_set("getattach.php",
					     session, NULL,
					     &params);

	free(params.argv);
	if (!reply)
		return -ENOENT;

	/* returned string is json-encoded base64 string; unescape it */
	if (reply[0] == '"')
		memmove(reply, reply+1, strlen(reply));
	if (reply[strlen(reply)-1] == '"')
		reply[strlen(reply)-1] = 0;

	p = reply;
	while (*p) {
		if (*p == '\\') {
			memmove(p, p + 1, strlen(p));
		} else {
			p++;
		}
	}

	*result = reply;
	return 0;
}
