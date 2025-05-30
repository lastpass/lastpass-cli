/*
 * https endpoints for shared folder manipulation
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

static inline void get_share_user_id(struct share_user *user, char **user_id)
{ 
	if (user->is_group)
	{
		xasprintf(user_id, "group:%s", user->uid);
	}
	else
	{
		xasprintf(user_id, "%s", user->uid);
	}
}

int lastpass_share_getinfo(const struct session *session, const char *shareid,
			   struct list_head *users)
{
	_cleanup_free_ char *reply = NULL;
	size_t len;

	reply = http_post_lastpass("share.php", session, &len,
				   "sharejs", "1", "getinfo", "1",
				   "id", shareid, "xmlr", "1", NULL);
	if (!reply)
		return -EPERM;

	xml_parse_share_getinfo(reply, users);
	return 0;
}

static
int lastpass_share_get_user_by_uid(const struct session *session,
				   const char *uid,
				   struct share_user *user)
{
	_cleanup_free_ char *reply = NULL;
	_cleanup_free_ char *uid_param;
	size_t len;

	xasprintf(&uid_param, "{\"%s\":{}}", uid);

	/* get the pubkey for the user/group */
	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "getpubkey", "1",
				   "uid", uid_param,
				   "xmlr", "1", NULL);

	return xml_parse_share_getpubkey(reply, user);
}

static
int lastpass_share_get_users_by_username(const struct session *session,
					 const char *username,
					 struct list_head *users)
{
	_cleanup_free_ char *reply = NULL;
	_cleanup_free_ char *uid_param;
	size_t len;

	xasprintf(&uid_param, "{\"%s\":{}}", username);

	/* get the pubkey for the user/group */
	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "getpubkey", "1",
				   "uid", uid_param,
				   "xmlr", "1", NULL);

	return xml_parse_share_getpubkeys(reply, users);
}

int lastpass_share_user_add(const struct session *session,
			    struct share *share,
			    struct share_user *user)
{
	_cleanup_free_ char *reply = NULL;
	_cleanup_free_ char *enc_share_name = NULL;
	_cleanup_free_ char *hex_share_key = NULL;
	_cleanup_free_ unsigned char *enc_share_key = NULL;
	_cleanup_free_ char *hex_enc_share_key = NULL;
	int ret;
	size_t len;

	struct list_head user_list;
	struct share_user *share_user, *tmp;

	INIT_LIST_HEAD(&user_list);

	ret = lastpass_share_get_users_by_username(session, user->username,
						   &user_list);
	if (ret)
		die("Unable to lookup user %s (%d)\n", user->username, ret);

	list_for_each_entry_safe(share_user, tmp, &user_list, list) {

		/* encrypt sharename with sharekey */
		enc_share_name = encrypt_and_base64(share->name, share->key);

		/* encrypt sharekey with user's pubkey */
		bytes_to_hex(share->key, &hex_share_key, sizeof(share->key));

		size_t enc_share_key_len = share_user->sharing_key.len;

		if (enc_share_key_len) {
			enc_share_key = xmalloc(enc_share_key_len);

			ret = cipher_rsa_encrypt(hex_share_key, &share_user->sharing_key,
						enc_share_key, &enc_share_key_len);
			if (ret)
				die("Unable to encrypt sharing key with pubkey (%d)\n",
					ret);

			bytes_to_hex(enc_share_key, &hex_enc_share_key,
					enc_share_key_len);

			reply = http_post_lastpass("share.php", session, &len,
						"token", session->token,
						"id", share->id,
						"update", "1",
						"add", "1",
						"notify", "1",
						"username0", share_user->username,
						"cgid0", share_user->cgid ? share_user->cgid : "",
						"sharekey0", hex_enc_share_key,
						"sharename", enc_share_name,
						"name", share->name,
						"readonly", bool_str(user->read_only),
						"give", bool_str(!user->hide_passwords),
						"canadminister", bool_str(user->admin),
						"xmlr", "1", NULL);
		} else {
			reply = http_post_lastpass("share.php", session, &len,
						"token", session->token,
						"id", share->id,
						"update", "1",
						"add", "1",
						"notify", "1",
						"msfusername0", share_user->username,
						"msfcgid0", share_user->cgid ? share_user->cgid : "",
						"msfreadonly0", bool_str(user->read_only),
						"msfcanadminister0", bool_str(user->admin),
						"msfgive0", bool_str(!user->hide_passwords),
						"sharename", enc_share_name,
						"name", share->name,
						"readonly", bool_str(user->read_only),
						"give", bool_str(!user->hide_passwords),
						"canadminister", bool_str(user->admin),
						"xmlr", "1", NULL);
		}

		free(share_user);
	}

	if (!reply)
		return -EPERM;

	return 0;
}

int lastpass_share_user_mod(const struct session *session,
			    struct share *share,
			    struct share_user *user)
{
	_cleanup_free_ char *reply = NULL;
	size_t len;

	_cleanup_free_ char *user_id = NULL;

	get_share_user_id(user, &user_id);

	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "id", share->id,
				   "up", "1",
				   "edituser", "1",
				   "uid", user_id,
				   "readonly", user->read_only ? "on" : "",
				   "give", !user->hide_passwords ? "on" : "",
				   "canadminister", user->admin ? "on" : "",
				   "xmlr", "1", NULL);
		   
	if (!reply)
		return -EPERM;

	return 0;
}

int lastpass_share_user_del(const struct session *session, const char *shareid,
			    struct share_user *user)
{
	char *reply = NULL;
	size_t len;
	
	_cleanup_free_ char *user_id = NULL;

	get_share_user_id(user, &user_id);
	
	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "id", shareid,
				   "update", "1",
				   "delete", "1",
				   "uid", user_id,
				   "xmlr", "1", NULL);

	free(reply);
	return 0;
}

int lastpass_share_create(const struct session *session, const char *sharename)
{
	_cleanup_free_ char *reply = NULL;
	_cleanup_free_ char *sf_username;
	_cleanup_free_ char *enc_share_name = NULL;
	_cleanup_free_ char *hex_share_key = NULL;
	_cleanup_free_ unsigned char *enc_share_key = NULL;
	_cleanup_free_ char *sf_fullname = NULL;
	_cleanup_free_ char *hex_enc_share_key = NULL;
	_cleanup_free_ char *hex_hash = NULL;

	unsigned char key[SHA256_DIGEST_LENGTH];
	struct share_user user;
	size_t len;
	unsigned int i;
	int ret;

	/* strip off "Shared-" part if included, we add it later */
	if (!strncmp(sharename, "Shared-", 7))
		sharename += 7;

	ret = lastpass_share_get_user_by_uid(session, session->uid, &user);
	if (ret)
		die("Unable to get pubkey for your user (%d)\n", ret);

	xasprintf(&sf_fullname, "Shared-%s", sharename);
	xasprintf(&sf_username, "%s-%s", user.username, sf_fullname);
	for (i=0; i < strlen(sf_username); i++)
		if (sf_username[i] == ' ')
			sf_username[i] = '_';

	get_random_bytes(key, sizeof(key));
	bytes_to_hex(key, &hex_share_key, sizeof(key));

	hex_hash = cipher_multi_sha256_hex(2, xstrlower(sf_username), hex_share_key);
	hex_hash = cipher_multi_sha256_hex(2, hex_hash, hex_share_key);

	/*
	 * Sharing key is hex-encoded then RSA-encrypted with our pubkey.
	 * Shared folder name is AES-encrypted with the sharing key.
	 */
	size_t enc_share_key_len = user.sharing_key.len;
	enc_share_key = xmalloc(enc_share_key_len);
	ret = cipher_rsa_encrypt(hex_share_key, &user.sharing_key,
				 enc_share_key, &enc_share_key_len);
	if (ret)
		die("Unable to RSA encrypt the sharing key (%d)", ret);

	bytes_to_hex(enc_share_key, &hex_enc_share_key, enc_share_key_len);

	enc_share_name = encrypt_and_base64(sf_fullname, key);

	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "id", "0",
				   "update", "1",
				   "newusername", sf_username,
				   "newhash", hex_hash,
				   "sharekey", hex_enc_share_key,
				   "name", sf_fullname,
				   "sharename", enc_share_name,
				   "xmlr", "1", NULL);

	if (!reply)
		return -EPERM;

	return 0;
}

int lastpass_share_delete(const struct session *session, struct share *share)
{
	char *reply = NULL;
	size_t len;

	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "id", share->id,
				   "delete", "1",
				   "xmlr", "1", NULL);
	free(reply);
	return 0;
}

/*
 * Move a site into or out of a shared folder.
 *
 * account should already be encrypted with the new share key.
 * orig_folder or account->share may be null, indicating the
 * transition to or from a regular site and a shared folder.
 */
int lastpass_share_move(const struct session *session,
			struct account *account,
			struct share *orig_folder)
{
	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *reply = NULL;

	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	if (!account->share && !orig_folder)
		return 0;

	bytes_to_hex((unsigned char *) account->url, &url, strlen(account->url));

	if (session->feature_flag.url_encryption_enabled) {
		http_post_add_params(&params,
			"token", session->token,
			"cmd", "uploadaccounts",
			"aid0", account->id,
			"name0", account->name_encrypted,
			"grouping0", account->group_encrypted,
			"url0", account->url_encrypted,
			"username0", account->username_encrypted,
			"password0", account->password_encrypted,
			"pwprotect0", account->pwprotect ? "on" : "off",
			"extra0", account->note_encrypted,
			"todelete", account->id, NULL);
	} else {
		http_post_add_params(&params,
			"token", session->token,
			"cmd", "uploadaccounts",
			"aid0", account->id,
			"name0", account->name_encrypted,
			"grouping0", account->group_encrypted,
			"url0", url,
			"username0", account->username_encrypted,
			"password0", account->password_encrypted,
			"pwprotect0", account->pwprotect ? "on" : "off",
			"extra0", account->note_encrypted,
			"todelete", account->id, NULL);
	}

	if (account->share) {
		http_post_add_params(&params,
				     "sharedfolderid", account->share->id,
				     NULL);
	}

	if (orig_folder) {
		http_post_add_params(&params,
				     "origsharedfolderid", orig_folder->id,
				     NULL);
	}

	if (session->feature_flag.url_logging_enabled) {
		http_post_add_params(&params, "recordUrl", url, NULL);
	}

	reply = http_post_lastpass_param_set("lastpass/api.php",
					     session, NULL,
					     &params);

	free(params.argv);

	if (!reply)
		return -EINVAL;

	return xml_api_err(reply);
}

int lastpass_share_get_limits(const struct session *session,
			      struct share *share,
			      struct share_user *user,
			      struct share_limit *ret_limit)
{
	_cleanup_free_ char *reply = NULL;
	size_t len;

	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "id", share->id,
				   "limit", "1",
				   "uid", user->uid,
				   "xmlr", "1", NULL);

	xml_parse_share_get_limits(reply, ret_limit);
	return 0;
}

int lastpass_share_set_limits(const struct session *session,
			      struct share *share,
			      struct share_user *user,
			      struct share_limit *limit)
{
	char *reply = NULL;
	_cleanup_free_ char *aid_buf = NULL;
	char numaids_str[30] = {0};
	struct share_limit_aid *aid;
	int numaids = 0;
	size_t alloc_len = 0;
	size_t len;

	list_for_each_entry(aid, &limit->aid_list, list) {
		alloc_len += strlen(aid->aid) + 1 /* comma or null */;
		numaids++;
	}

	aid_buf = xcalloc(alloc_len, 1);

	list_for_each_entry(aid, &limit->aid_list, list) {
		strlcat(aid_buf, aid->aid, alloc_len);
		strlcat(aid_buf, ",", alloc_len);
	}
	aid_buf[alloc_len-1] = '\0';

	snprintf(numaids_str, sizeof(numaids_str), "%d", numaids);

	reply = http_post_lastpass("share.php", session, &len,
				   "token", session->token,
				   "id", share->id,
				   "limit", "1",
				   "edit", "1",
				   "uid", user->uid,
				   "numaids", numaids_str,
				   "hidebydefault", bool_str(limit->whitelist),
				   "aids", aid_buf,
				   "xmlr", "1", NULL);

	free(reply);
	return 0;
}
