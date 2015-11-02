/*
 * session handling routines
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
#include "xml.h"
#include "config.h"
#include "util.h"
#include "cipher.h"
#include <sys/mman.h>
#include <string.h>

struct session *session_new(void)
{
	return new0(struct session, 1);
}
void session_free(struct session *session)
{
	if (!session)
		return;
	free(session->uid);
	free(session->sessionid);
	free(session->token);
	free(session->private_key.key);
	free(session);
}
bool session_is_valid(struct session *session)
{
	return session && session->uid && session->sessionid && session->token;
}
void session_set_private_key(struct session *session, unsigned const char key[KDF_HASH_LEN], const char *key_hex)
{
	#define start_str "LastPassPrivateKey<"
	#define end_str ">LastPassPrivateKey"
	size_t len;
	_cleanup_free_ unsigned char *encrypted_key = NULL;
	_cleanup_free_ char *decrypted_key = NULL;
	unsigned char *encrypted_key_start;
	char *start, *end;

	len = strlen(key_hex);
	if (len % 2 != 0)
		die("Key hex in wrong format.");
	len /= 2;

	len += 16 /* IV */ + 1 /* pound symbol */;
	encrypted_key = xcalloc(len + 1, 1);
	encrypted_key[0] = '!';
	memcpy(&encrypted_key[1], key, 16);
	encrypted_key_start = &encrypted_key[17];
	hex_to_bytes(key_hex, &encrypted_key_start);
	decrypted_key = cipher_aes_decrypt(encrypted_key, len, key);
	if (!decrypted_key)
		warn("Could not decrypt private key.");
	else {
		start = strstr(decrypted_key, start_str);
		end = strstr(decrypted_key, end_str);
		if (!start || !end || end <= start)
			warn("Could not decode decrypted private key.");
		else {
			start += strlen(start_str);
			*end = '\0';

			len = strlen(start);
			if (len % 2 != 0)
				die("Invalid private key after decryption and decoding.");
			len /= 2;

			hex_to_bytes(start, &session->private_key.key);
			session->private_key.len = len;
			mlock(session->private_key.key, len);
		}
	}
	#undef start_str
	#undef end_str
}
void session_save(struct session *session, unsigned const char key[KDF_HASH_LEN])
{
	config_write_encrypted_string("session_uid", session->uid, key);
	config_write_encrypted_string("session_sessionid", session->sessionid, key);
	config_write_encrypted_string("session_token", session->token, key);
	config_write_encrypted_buffer("session_privatekey", (char *)session->private_key.key, session->private_key.len, key);
}
struct session *sesssion_load(unsigned const char key[KDF_HASH_LEN])
{
	struct session *session = session_new();
	session->uid = config_read_encrypted_string("session_uid", key);
	session->sessionid = config_read_encrypted_string("session_sessionid", key);
	session->token = config_read_encrypted_string("session_token", key);
	session->private_key.len = config_read_encrypted_buffer("session_privatekey", &session->private_key.key, key);
	mlock(session->private_key.key, session->private_key.len);

	if (session_is_valid(session))
		return session;
	else {
		session_free(session);
		return NULL;
	}
}
