/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "endpoints.h"
#include "http.h"
#include "version.h"
#include "xml.h"
#include "config.h"
#include "util.h"
#include "upload-queue.h"
#include <string.h>
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
	_cleanup_free_ char *blob;

	blob = http_post_lastpass("getaccts.php", session->sessionid, &len, "mobile", "1", "requestsrc", "cli", "hasplugin", LASTPASS_CLI_VERSION, NULL);
	if (!blob || !len)
		return NULL;
	config_write_encrypted_buffer("blob", blob, len, key);
	return blob_parse(blob, len, key, &session->private_key);
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

static char *stringify_fields(const struct field *field_head)
{
	char *field_str, *fields = NULL;

	for (const struct field *field = field_head; field; field = field->next) {
		field_str = stringify_field(field);
		xstrappend(&fields, field_str);
		free(field_str);
	}
	if (fields)
		xstrappend(&fields, "0\taction\t\taction\n0\tmethod\t\tmethod\n");
	else
		fields = xstrdup("");

	field_str = NULL;
	bytes_to_hex(fields, &field_str, strlen(fields));
	free(fields);

	return field_str;
}

void lastpass_update_account(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const struct account *account, struct blob *blob)
{
	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *fields = NULL;

	bytes_to_hex(account->url, &url, strlen(account->url));
	fields = stringify_fields(account->field_head);

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

	reply = http_post_lastpass("login_check.php", session->sessionid, NULL, NULL);
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
		upload_queue_enqueue(sync, key, session, "loglogin.php", "id", account->id, "method", "cl", NULL);
	else
		upload_queue_enqueue(sync, key, session, "loglogin.php", "id", account->id, "method", "cl", "sharedfolderid", account->share->id, NULL);
}

