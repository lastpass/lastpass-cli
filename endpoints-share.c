/*
 * Copyright (c) 2014-2015 LastPass.
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
	bytes_to_hex((char *) share->key, &hex_share_key, sizeof(share->key));

	size_t enc_share_key_len = user->sharing_key.len;
	enc_share_key = xmalloc(enc_share_key_len);

	ret = cipher_rsa_encrypt(hex_share_key, &user->sharing_key,
				 enc_share_key, &enc_share_key_len);
	if (ret)
		die("Unable to encrypt sharing key with pubkey (%d)\n", ret);

	bytes_to_hex((char * ) enc_share_key, &hex_enc_share_key, enc_share_key_len);

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
