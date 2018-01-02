/*
 * command for changing master password
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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301 USA.
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
#include <errno.h>
#include <string.h>
#include "blob.h"
#include "kdf.h"
#include "cmd.h"
#include "endpoints.h"
#include "config.h"
#include "password.h"
#include "cipher.h"
#include "session.h"

static void show_status_bar(const char *operation,
			    unsigned int cur, unsigned int max)
{
	char progress[41] = {0};
	size_t len;

	if (!max)
		max = 1;

	if (cur > max)
		cur = max;

	len = (cur * (sizeof(progress) - 1)) / max;
	if (len)
		memset(progress, '=', len);

	terminal_fprintf(stderr, TERMINAL_FG_CYAN "%s " TERMINAL_RESET
                     TERMINAL_FG_BLUE "[%-*s] " TERMINAL_RESET
                     TERMINAL_FG_CYAN "%d/%d     \r" TERMINAL_RESET,
                     operation, (int) sizeof(progress)-1, progress, cur, max);
}

static void reencrypt(struct session *session,
		      struct pwchange_info *info,
		      unsigned char key[KDF_HASH_LEN],
		      unsigned char new_key[KDF_HASH_LEN])
{
	struct pwchange_field *field;
	struct pwchange_su_key *su_key;
	struct private_key tmp;
	unsigned int n_fields = 0;
	unsigned int i = 0;
	unsigned int n_required = 0;
	unsigned int errors = 0;

	/* count how many things we'll encrypt */
	list_for_each_entry(field, &info->fields, list) {
		n_fields++;
	}
	list_for_each_entry(su_key, &info->su_keys, list) {
		n_fields++;
	}
	/* plus sharing key */
	n_fields++;

	show_status_bar("Re-encrypting", i++, n_fields);

	/* decrypt and re-encrypt RSA sharing key */
	cipher_decrypt_private_key(info->privkey_encrypted, key, &tmp);
	if (tmp.len != session->private_key.len ||
	    memcmp(session->private_key.key, tmp.key, session->private_key.len)) {
		die("Server and session private key don't match! Try lpass sync first.");
	}

	info->new_privkey_encrypted =
		cipher_encrypt_private_key(&tmp, new_key);

	secure_clear(tmp.key, tmp.len);
	free(tmp.key);

	/* reencrypt site info */
	list_for_each_entry(field, &info->fields, list) {
		show_status_bar("Re-encrypting", i++, n_fields);
		if (!field->optional)
			n_required++;

		char *ptext = cipher_aes_decrypt_base64(field->old_ctext, key);
		if (!ptext) {
			if (!field->optional)
				errors++;
			ptext = " ";
		}
		field->new_ctext = encrypt_and_base64(ptext, new_key);
	}

	/*
	 * Fail if > 10% decryption errors.  This indicates the blob and key
	 * are out of sync somehow, or that user has reverted a password
	 * change but some entries are encrypted with the new key.
	 */
	if (errors > n_required / 10)
		die("Too many decryption failures.");

	/* encrypt recovery copy of our key */
	list_for_each_entry(su_key, &info->su_keys, list) {
		show_status_bar("Re-encrypting", i++, n_fields);

		size_t enc_key_len = su_key->sharing_key.len;
		unsigned char *enc_key = xmalloc(enc_key_len);

		cipher_rsa_encrypt_bytes(new_key, KDF_HASH_LEN,
					 &su_key->sharing_key,
					 enc_key, &enc_key_len);
		bytes_to_hex(enc_key, &su_key->new_enc_key, enc_key_len);
		free(enc_key);
	}

	show_status_bar("Re-encrypting", n_fields, n_fields);

	info->new_privkey_hash = cipher_sha256_hex((unsigned char *)
		info->new_privkey_encrypted,
		strlen(info->new_privkey_encrypted));
	info->new_key_hash = cipher_sha256_hex(new_key, KDF_HASH_LEN);

	printf("\n");
}

int cmd_passwd(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);

	unsigned char key[KDF_HASH_LEN];
	unsigned char new_key[KDF_HASH_LEN];
	char hex[KDF_HEX_LEN];
	char new_hex[KDF_HEX_LEN];
	struct session *session = NULL;
	struct blob *blob;
	int ret;
	_cleanup_free_ char *password = NULL;
	_cleanup_free_ char *new_password = NULL;
	_cleanup_free_ char *pw2 = NULL;
	_cleanup_free_ char *username = NULL;
	int iterations;
	bool match;
	struct pwchange_info info;

	/* load existing session, if present */
	init_all(BLOB_SYNC_YES, key, &session, &blob);

	username = config_read_string("username");
	iterations = lastpass_iterations(username);
	if (!iterations)
		die("Unable to fetch iteration count. Check your internet connection and be sure your username is valid.");

	/* reprompt for old mpw */
	password = password_prompt("Current Master Password", NULL,
		"Please enter the current LastPass master password for <%s>.",
		username);

	if (!password)
		die("Failed to enter password.");

	kdf_login_key(username, password, iterations, hex);
	secure_clear_str(password);

	/* prompt for new pw */
	new_password = password_prompt("New Master Password", NULL,
		"Please enter the new LastPass master password for <%s>.",
		username);

	pw2 = password_prompt("Confirm New Master Password", NULL,
		"Please retype the new LastPass master password for <%s>.",
		username);

	if (!new_password || !pw2)
		die("Failed to enter new password.");

	match = strcmp(new_password, pw2) == 0;
	secure_clear_str(pw2);

	if (!match)
		die("Bad password: passwords don't match.");

	if (strlen(new_password) < 8)
		die("Bad password: too short.");

	kdf_decryption_key(username, new_password, iterations, new_key);
	kdf_login_key(username, new_password, iterations, new_hex);
	secure_clear_str(new_password);

	/*
	 * Fetch the data to reencrypt.  We may learn at this point that the
	 * current password was incorrect, so handle that accordingly.
	 */
	terminal_printf(TERMINAL_FG_CYAN "Fetching data...\n" TERMINAL_RESET);
	ret = lastpass_pwchange_start(session, username, hex, &info);
	if (ret) {
		if (ret == -EPERM)
			die("Incorrect password.  Password not changed.");
		else
			die("Error changing password (error=%d)", ret);
	}

	/* reencrypt */
	reencrypt(session, &info, key, new_key);

	terminal_printf(TERMINAL_FG_CYAN "Uploading...\n" TERMINAL_RESET);

	_cleanup_free_ char *enc_username = encrypt_and_base64(username, new_key);
	ret = lastpass_pwchange_complete(session, username, enc_username,
					 new_hex, iterations, &info);

	if (ret)
		die("Password change failed.");

	session_kill();
	terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "Success" TERMINAL_RESET ": Password changed and logged out.\n");
	return 0;
}
