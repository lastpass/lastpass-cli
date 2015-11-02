/*
 * https endpoints for shared folder manipulation
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

int lastpass_share_getinfo(const struct session *session, const char *shareid,
			   struct list_head *users)
{
	_cleanup_free_ char *reply = NULL;
	size_t len;

	reply = http_post_lastpass("share.php", session->sessionid, &len,
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
	size_t len;

	/* get the pubkey for the user/group */
	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "token", session->token,
				   "getpubkey", "1",
				   "uid", uid,
				   "xmlr", "1", NULL);

	return xml_parse_share_getpubkey(reply, user);
}

static
int lastpass_share_get_user_by_username(const struct session *session,
					const char *username,
					struct share_user *user)
{
	_cleanup_free_ char *reply = NULL;
	_cleanup_free_ char *uid_param;
	size_t len;

	xasprintf(&uid_param, "{\"%s\":{}}", username);

	/* get the pubkey for the user/group */
	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "token", session->token,
				   "getpubkey", "1",
				   "uid", uid_param,
				   "xmlr", "1", NULL);

	return xml_parse_share_getpubkey(reply, user);
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

	ret = lastpass_share_get_user_by_username(session, user->username, user);
	if (ret)
		die("Unable to lookup user %s (%d)\n", user->username, ret);

	/* encrypt sharename with sharekey */
	enc_share_name = encrypt_and_base64(share->name, share->key);

	/* encrypt sharekey with user's pubkey */
	bytes_to_hex(share->key, &hex_share_key, sizeof(share->key));

	size_t enc_share_key_len = user->sharing_key.len;
	enc_share_key = xmalloc(enc_share_key_len);

	ret = cipher_rsa_encrypt(hex_share_key, &user->sharing_key,
				 enc_share_key, &enc_share_key_len);
	if (ret)
		die("Unable to encrypt sharing key with pubkey (%d)\n", ret);

	bytes_to_hex(enc_share_key, &hex_enc_share_key, enc_share_key_len);

	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "token", session->token,
				   "id", share->id,
				   "update", "1",
				   "add", "1",
				   "notify", "1",
				   "uid0", user->uid,
				   "sharekey0", hex_enc_share_key,
				   "sharename", enc_share_name,
				   "readonly", bool_str(user->read_only),
				   "give", bool_str(!user->hide_passwords),
				   "canadminister", bool_str(user->admin),
				   "xmlr", "1", NULL);

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

	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "token", session->token,
				   "id", share->id,
				   "up", "1",
				   "edituser", "1",
				   "uid", user->uid,
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
	_cleanup_free_ char *reply = NULL;
	size_t len;

	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "token", session->token,
				   "id", shareid,
				   "update", "1",
				   "delete", "1",
				   "uid", user->uid,
				   "xmlr", "1", NULL);
	return 0;
}

int lastpass_share_create(const struct session *session, const char *sharename)
{
	_cleanup_free_ char *reply = NULL;
	_cleanup_free_ char *sf_username;
	_cleanup_free_ char *enc_share_name = NULL;
	_cleanup_free_ char *hex_share_key = NULL;
	_cleanup_free_ char *hex_hash = NULL;
	_cleanup_free_ unsigned char *enc_share_key = NULL;
	_cleanup_free_ char *sf_fullname = NULL;
	_cleanup_free_ char *hex_enc_share_key = NULL;

	unsigned char pw[KDF_HASH_LEN * 2];
	unsigned char key[KDF_HASH_LEN];
	char hash[KDF_HEX_LEN];
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

	xasprintf(&sf_username, "%s-%s", user.username, sharename);
	for (i=0; i < strlen(sf_username); i++)
		if (sf_username[i] == ' ')
			sf_username[i] = '_';

	/*
	 * generate random sharing key.  kdf_decryption_key wants a string so
	 * we remove any zeroes except the terminator.
	 */
	get_random_bytes(pw, sizeof(pw));
	pw[sizeof(pw)-1] = 0;
	for (i=0; i < sizeof(pw)-1; i++) {
		if (!pw[i])
			pw[i] = (unsigned char) range_rand(1, 256);
	}

	kdf_decryption_key(sf_username, (char *) pw, 1, key);
	kdf_login_key(sf_username, (char *) pw, 1, hash);
	bytes_to_hex(key, &hex_share_key, sizeof(key));

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

	xasprintf(&sf_fullname, "Shared-%s", sharename);
	enc_share_name = encrypt_and_base64(sf_fullname, key);

	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "token", session->token,
				   "id", "0",
				   "update", "1",
				   "newusername", sf_username,
				   "newhash", hash,
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
	_cleanup_free_ char *reply = NULL;
	size_t len;

	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "token", session->token,
				   "id", share->id,
				   "delete", "1",
				   "xmlr", "1", NULL);
	return 0;
}
