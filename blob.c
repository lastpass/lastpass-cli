/*
 * encrypted vault parsing
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
#include "blob.h"
#include "config.h"
#include "endpoints.h"
#include "cipher.h"
#include "util.h"
#include "upload-queue.h"
#include "version.h"
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#if defined(__APPLE__) && defined(__MACH__)
#include <libkern/OSByteOrder.h>
#define htobe32(x) OSSwapHostToBigInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#else
# if (defined(__unix__) || defined(unix)) && !defined(USG)
#  include <sys/param.h>
# endif
# if defined(BSD)
#  include <sys/endian.h>
# else
#  include <endian.h>
# endif
#endif

struct app *account_to_app(const struct account *account)
{
	return container_of(account, struct app, account);
}

void share_free(struct share *share)
{
	if (!share)
		return;

	free(share->name);
	free(share->id);
	free(share->chunk);
	free(share);
}

void field_free(struct field *field)
{
	if (!field)
		return;

	free(field->name);
	free(field->value);
	free(field->value_encrypted);
	free(field->type);
	free(field);
}

void account_free_contents(struct account *account)
{
	struct field *field, *tmp;

	free(account->id);
	free(account->name);
	free(account->group);
	free(account->fullname);
	free(account->url);
	free(account->username);
	free(account->password);
	free(account->note);
	free(account->name_encrypted);
	free(account->group_encrypted);
	free(account->username_encrypted);
	free(account->password_encrypted);
	free(account->note_encrypted);
	free(account->attachkey);
	free(account->attachkey_encrypted);

	list_for_each_entry_safe(field, tmp, &account->field_head, list) {
		field_free(field);
	}
}

void app_free(struct app *app)
{
	account_free_contents(&app->account);
	free(app->appname);
	free(app->extra);
	free(app->extra_encrypted);
	free(app->wintitle);
	free(app->wininfo);
	free(app->exeversion);
	free(app->warnversion);
	free(app->exehash);
}

bool account_is_group(struct account *account)
{
	return !strcmp(account->url, "http://group");
}

static
bool account_is_secure_note(const struct account *account)
{
	return !strcmp(account->url, "http://sn");
}

struct app *new_app()
{
	struct app *app = new0(struct app, 1);
	struct account *account = &app->account;

	app->appname = xstrdup("");
	app->extra = xstrdup("");
	app->extra_encrypted = xstrdup("");

	INIT_LIST_HEAD(&account->field_head);
	INIT_LIST_HEAD(&account->attach_head);
	account->is_app = true;

	return app;
}

struct account *new_account()
{
	struct account *account = new0(struct account, 1);
	INIT_LIST_HEAD(&account->field_head);
	INIT_LIST_HEAD(&account->attach_head);
	return account;
}

void account_free(struct account *account)
{
	if (!account)
		return;

	if (account->is_app) {
		app_free(account_to_app(account));
		return;
	}

	account_free_contents(account);
	free(account);
}

void blob_free(struct blob *blob)
{
	if (!blob)
		return;

	struct account *account, *tmp;
	struct share *share, *tmp_share;

	list_for_each_entry_safe(account, tmp, &blob->account_head, list)
		account_free(account);

	list_for_each_entry_safe(share, tmp_share, &blob->share_head, list)
		share_free(share);

	free(blob);
}

struct blob_pos {
	const unsigned char *data;
	size_t len;
};

struct chunk {
	char name[4 + 1];
	const unsigned char *data;
	size_t len;
};

struct item {
	const unsigned char *data;
	size_t len;
};

static bool read_chunk(struct blob_pos *blob, struct chunk *chunk)
{
	if (blob->len < 4)
		return false;
	chunk->name[0] = blob->data[0];
	chunk->name[1] = blob->data[1];
	chunk->name[2] = blob->data[2];
	chunk->name[3] = blob->data[3];
	chunk->name[4] = '\0';
	blob->len -= 4;
	blob->data += 4;

	if (blob->len < sizeof(uint32_t))
		return false;
	chunk->len = be32toh(*((uint32_t *)blob->data));
	blob->len -= sizeof(uint32_t);
	blob->data += sizeof(uint32_t);

	if (chunk->len > blob->len)
		return false;
	chunk->data = blob->data;
	blob->data += chunk->len;
	blob->len -= chunk->len;

	return true;

}

static bool read_item(struct chunk *chunk, struct item *item)
{
	if (chunk->len < sizeof(uint32_t))
		return false;
	item->len = be32toh(*((uint32_t *)chunk->data));
	chunk->len -= sizeof(uint32_t);
	chunk->data += sizeof(uint32_t);

	if (item->len > chunk->len)
		return false;
	item->data = chunk->data;
	chunk->data += item->len;
	chunk->len -= item->len;

	return true;
}

static char *read_hex_string(struct chunk *chunk)
{
	struct item item;
	int result;
	char *str = NULL;

	if (!read_item(chunk, &item))
		return NULL;
	if (item.len == 0)
		return xstrdup("");

	result = hex_to_bytes((char *) item.data, (unsigned char **) &str);
	if (result) {
		free(str);
		return NULL;
	}
	return str;
}

static char *read_plain_string(struct chunk *chunk)
{
	struct item item;

	if (!read_item(chunk, &item))
		return NULL;

	if (item.len == 0)
		return xstrdup("");

	return xstrndup((char *) item.data, item.len);
}

static char *read_crypt_string(struct chunk *chunk, const unsigned char key[KDF_HASH_LEN], char **stored_base64)
{
	struct item item;
	char *ptext;

	if (!read_item(chunk, &item))
		return NULL;
	if (stored_base64)
		*stored_base64 = cipher_base64(item.data, item.len);

	if (item.len == 0)
		return xstrdup("");

	ptext = cipher_aes_decrypt(item.data, item.len, key);
	if (!ptext)
		/* don't fail whole blob if this item cannot be decrypted */
		return xstrdup("");

	return ptext;
}

static int read_boolean(struct chunk *chunk)
{
	struct item item;

	if (!read_item(chunk, &item))
		return -1;
	if (item.len != 1)
		return 0;

	return item.data[0] == '1';
}

#define entry_plain_at(base, var) do { \
	char *__entry_val__ = read_plain_string(chunk); \
	if (!__entry_val__) \
		goto error; \
	base->var = __entry_val__; \
	} while (0)
#define entry_plain(var) entry_plain_at(parsed, var)
#define entry_hex_at(base, var) do { \
	char *__entry_val__ = read_hex_string(chunk); \
	if (!__entry_val__) \
		goto error; \
	base->var = __entry_val__; \
	} while (0)
#define entry_hex(var) entry_hex_at(parsed, var)
#define entry_boolean(var) do { \
	int __entry_val__ = read_boolean(chunk); \
	if (__entry_val__ < 0) \
		goto error; \
	parsed->var = __entry_val__; \
	} while (0)
#define entry_crypt_at(base, var) do { \
	char *__entry_val__ = read_crypt_string(chunk, key, &base->var##_encrypted); \
	if (!__entry_val__) \
		goto error; \
	base->var = __entry_val__; \
	} while (0)
#define entry_crypt(var) entry_crypt_at(parsed, var)
#define skip(placeholder) do { \
	struct item skip_item; \
	if (!read_item(chunk, &skip_item)) \
		goto error; \
	} while (0)

static struct account *account_parse(struct chunk *chunk, const unsigned char key[KDF_HASH_LEN])
{
	struct account *parsed = new_account();

	entry_plain(id);
	entry_crypt(name);
	entry_crypt(group);
	entry_hex(url);
	entry_crypt(note);
	entry_boolean(fav);
	skip(sharedfromaid);
	entry_crypt(username);
	entry_crypt(password);
	entry_boolean(pwprotect);
	skip(genpw);
	skip(sn);
	entry_plain(last_touch);
	skip(autologin);
	skip(never_autofill);
	skip(realm_data);
	skip(fiid);
	skip(custom_js);
	skip(submit_id);
	skip(captcha_id);
	skip(urid);
	skip(basic_auth);
	skip(method);
	skip(action);
	skip(groupid);
	skip(deleted);
	entry_plain(attachkey_encrypted);
	entry_boolean(attachpresent);
	skip(individualshare);
	skip(notetype);
	skip(noalert);
	entry_plain(last_modified_gmt);
	skip(hasbeenshared);
	skip(last_pwchange_gmt);
	skip(created_gmt);
	skip(vulnerable);

	if (parsed->name[0] == 16)
		parsed->name[0] = '\0';
	if (parsed->group[0] == 16)
		parsed->group[0] = '\0';

	if (strlen(parsed->attachkey_encrypted)) {
		parsed->attachkey = cipher_aes_decrypt_base64(
			parsed->attachkey_encrypted, key);
	}
	if (!parsed->attachkey)
		parsed->attachkey = xstrdup("");

	/* use name as 'fullname' only if there's no assigned group */
	if (strlen(parsed->group) &&
	    (strlen(parsed->name) || account_is_group(parsed)))
		xasprintf(&parsed->fullname, "%s/%s", parsed->group, parsed->name);
	else
		parsed->fullname = xstrdup(parsed->name);

	return parsed;

error:
	account_free(parsed);
	return NULL;
}

static struct field *field_parse(struct chunk *chunk, const unsigned char key[KDF_HASH_LEN])
{
	struct field *parsed = new0(struct field, 1);

	entry_plain(name);
	entry_plain(type);
	if (!strcmp(parsed->type, "email") || !strcmp(parsed->type, "tel") || !strcmp(parsed->type, "text") || !strcmp(parsed->type, "password") || !strcmp(parsed->type, "textarea"))
		entry_crypt(value);
	else
		entry_plain(value);
	entry_boolean(checked);

	return parsed;

error:
	field_free(parsed);
	return NULL;
}

static struct field *app_field_parse(struct chunk *chunk, const unsigned char key[KDF_HASH_LEN])
{
	struct field *parsed = new0(struct field, 1);

	entry_plain(name);
	entry_crypt(value);
	entry_plain(type);

	return parsed;
error:
	field_free(parsed);
	return NULL;
}

static struct share *share_parse(struct chunk *chunk, const struct private_key *private_key)
{
	struct share *parsed = new0(struct share, 1);
	struct item item;
	_cleanup_free_ unsigned char *ciphertext = NULL;
	_cleanup_free_ char *hex_key = NULL;
	_cleanup_free_ unsigned char *key = NULL;
	_cleanup_free_ char *base64_name = NULL;
	size_t len;

	if (!private_key)
		goto error;

	if (chunk->len) {
		parsed->chunk_len = chunk->len;
		parsed->chunk = xmalloc(chunk->len);
		memcpy(parsed->chunk, chunk->data, chunk->len);
	}

	entry_plain(id);

	if (!read_item(chunk, &item) || item.len == 0 || item.len % 2 != 0)
		goto error;
	hex_to_bytes((char *) item.data, &ciphertext);
	hex_key = cipher_rsa_decrypt(ciphertext, item.len / 2, private_key);
	if (!hex_key)
		goto error;
	len = strlen(hex_key);
	if (len % 2 != 0)
		goto error;
	len /= 2;
	if (len != KDF_HASH_LEN)
		goto error;
	hex_to_bytes(hex_key, &key);
	mlock(parsed->key, KDF_HASH_LEN);
	memcpy(parsed->key, key, KDF_HASH_LEN);

	base64_name = read_plain_string(chunk);
	parsed->name = cipher_aes_decrypt_base64(base64_name, parsed->key);
	if (!parsed->name)
		goto error;

	entry_boolean(readonly);

	return parsed;

error:
	share_free(parsed);
	return NULL;
}

static struct app *app_parse(struct chunk *chunk, const unsigned char key[KDF_HASH_LEN])
{
	struct app *app = new_app();
	struct account *parsed = &app->account;

	entry_plain(id);
	entry_hex_at(app, appname);
	entry_crypt_at(app, extra);
	entry_crypt(name);
	entry_crypt(group);
	entry_plain(last_touch);
	skip(fiid);
	entry_boolean(pwprotect);
	entry_boolean(fav);
	entry_plain_at(app, wintitle);
	entry_plain_at(app, wininfo);
	entry_plain_at(app, exeversion);
	skip(autologin);
	entry_plain_at(app, warnversion);
	entry_plain_at(app, exehash);

	parsed->username = xstrdup("");
	parsed->password = xstrdup("");
	parsed->note = xstrdup("");
	parsed->url = xstrdup("");

	if (strlen(parsed->group) &&
	    (strlen(parsed->name) || account_is_group(parsed)))
		xasprintf(&parsed->fullname, "%s/%s", parsed->group, parsed->name);
	else
		parsed->fullname = xstrdup(parsed->name);

	return app;
error:
	app_free(app);
	return NULL;
}

static void attach_free(struct attach *attach)
{
	if (!attach)
		return;

	free(attach->id);
	free(attach->parent);
	free(attach->mimetype);
	free(attach->storagekey);
	free(attach->size);
	free(attach->filename);
	free(attach);
}

static struct attach *attach_parse(struct chunk *chunk)
{
	struct attach *parsed = new0(struct attach, 1);

	entry_plain(id);
	entry_plain(parent);
	entry_plain(mimetype);
	entry_plain(storagekey);
	entry_plain(size);
	entry_plain(filename);

	return parsed;

error:
	attach_free(parsed);
	return NULL;
}

#undef entry_plain
#undef entry_plain_at
#undef entry_hex
#undef entry_boolean
#undef entry_crypt
#undef entry_crypt_at
#undef skip

struct blob *blob_parse(const unsigned char *blob, size_t len, const unsigned char key[KDF_HASH_LEN], const struct private_key *private_key)
{
	struct blob_pos blob_pos = { .data = blob, .len = len };
	struct chunk chunk;
	struct account *account = NULL;
	struct field *field;
	struct share *share, *last_share = NULL;
	struct app *app = NULL;
	struct attach *attach;
	struct blob *parsed;
	_cleanup_free_ char *versionstr = NULL;

	parsed = new0(struct blob, 1);
	parsed->local_version = false;
	INIT_LIST_HEAD(&parsed->account_head);
	INIT_LIST_HEAD(&parsed->share_head);

	while (read_chunk(&blob_pos, &chunk)) {
		if (!strcmp(chunk.name, "LPAV")) {
			versionstr = xstrndup((char *) chunk.data, chunk.len);
			parsed->version = strtoull(versionstr, NULL, 10);
		} else if (!strcmp(chunk.name, "ACCT")) {
			account = account_parse(&chunk, last_share ? last_share->key : key);
			if (!account)
				goto error;

			if (last_share) {
				account->share = last_share;
				char *tmp = account->fullname;
				xasprintf(&account->fullname, "%s/%s",
					  last_share->name, tmp);
				free(tmp);
			}

			list_add(&account->list, &parsed->account_head);

		} else if (!strcmp(chunk.name, "ACFL") || !strcmp(chunk.name, "ACOF")) {
			if (!account)
				goto error;

			field = field_parse(&chunk, last_share ? last_share->key : key);
			if (!field)
				goto error;

			list_add_tail(&field->list, &account->field_head);
		} else if (!strcmp(chunk.name, "LOCL")) {
			parsed->local_version = true;
		} else if (!strcmp(chunk.name, "SHAR")) {
			share = share_parse(&chunk, private_key);
			last_share = share;
			if (share)
				list_add_tail(&share->list, &parsed->share_head);
		} else if (!strcmp(chunk.name, "AACT")) {
			app = app_parse(&chunk, last_share ? last_share->key : key);
			if (app)
				list_add_tail(&app->account.list, &parsed->account_head);
		} else if (!strcmp(chunk.name, "AACF")) {
			if (!app)
				goto error;
			field = app_field_parse(&chunk, last_share ? last_share->key : key);
			if (!field)
				goto error;
			list_add_tail(&field->list, &app->account.field_head);
		} else if (!strcmp(chunk.name, "ATTA")) {
			struct account *tmp;
			bool found = false;

			attach = attach_parse(&chunk);
			if (!attach)
				goto error;

			/* add attachment to the proper account's list */
			list_for_each_entry(tmp, &parsed->account_head, list) {
				if (!strcmp(tmp->id, attach->parent)) {
					found = true;
					list_add_tail(&attach->list, &tmp->attach_head);
					break;
				}
			}
			if (!found)
				attach_free(attach);
		}
	}

	if (!versionstr)
		goto error;
	return parsed;

error:
	blob_free(parsed);
	return NULL;
}

void buffer_init(struct buffer *buf)
{
	buf->len = 0;
	buf->max = 80;
	buf->bytes = xcalloc(buf->max, 1);
}

void buffer_append(struct buffer *buffer, void *bytes, size_t len)
{
	if (buffer->len + len > buffer->max) {
		buffer->max = buffer->len + len + 512;
		buffer->bytes = xrealloc(buffer->bytes, buffer->max);
	}
	memcpy(buffer->bytes + buffer->len, bytes, len);
	buffer->len += len;
}

void buffer_append_char(struct buffer *buf, char c)
{
	if (buf->len + 1 >= buf->max) {
		buf->max += 80;
		buf->bytes = xrealloc(buf->bytes, buf->max);
	}
	buf->bytes[buf->len++] = c;
	buf->bytes[buf->len] = '\0';
}

void buffer_append_str(struct buffer *buf, char *str)
{
	/*
	 * copy null terminator, but don't count in used len
         * so that append of multiple strings will work
         */
	buffer_append(buf, str, strlen(str) + 1);
	buf->len--;
}

static void write_item(struct buffer *buffer, char *bytes, size_t len)
{
	uint32_t be32len = htobe32(len);
	buffer_append(buffer, &be32len, sizeof(be32len));
	buffer_append(buffer, bytes, len);
}

static void write_plain_string(struct buffer *buffer, char *bytes)
{
	write_item(buffer, bytes, strlen(bytes));
}
static void write_hex_string(struct buffer *buffer, char *bytes)
{
	_cleanup_free_ char *hex = NULL;
	bytes_to_hex((unsigned char *) bytes, &hex, strlen(bytes));
	write_plain_string(buffer, hex);
}
static void write_crypt_string(struct buffer *buffer, char *enc_str)
{
	_cleanup_free_ unsigned char *encrypted = NULL;
	size_t len;

	/*
	 * enc_str is base64-encoded, but we write out raw bytes in
	 * the saved blob, so un-base64.
	 */
	len = cipher_unbase64(enc_str, &encrypted);
	write_item(buffer, (char *) encrypted, len);
}

static void write_boolean(struct buffer *buffer, bool yes)
{
	write_plain_string(buffer, yes ? "1" : "0");
}

static void write_chunk(struct buffer *dstbuffer, struct buffer *srcbuffer, char *tag)
{
	if (strlen(tag) != 4)
		return;
	buffer_append(dstbuffer, tag, 4);
	write_item(dstbuffer, srcbuffer->bytes, srcbuffer->len);
}

static void write_app_chunk(struct buffer *buffer, struct account *account)
{
	struct buffer accbuf, fieldbuf;
	struct field *field;
	struct app *app = account_to_app(account);

	memset(&accbuf, 0, sizeof(accbuf));
	write_plain_string(&accbuf, account->id);
	write_hex_string(&accbuf, app->appname);
	write_crypt_string(&accbuf, app->extra_encrypted);
	write_crypt_string(&accbuf, account->name_encrypted);
	write_crypt_string(&accbuf, account->group_encrypted);
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_boolean(&accbuf, account->pwprotect);
	write_boolean(&accbuf, account->fav);
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_chunk(buffer, &accbuf, "AACT");
	free(accbuf.bytes);
	list_for_each_entry(field, &account->field_head, list) {
		memset(&fieldbuf, 0, sizeof(fieldbuf));
		write_plain_string(&fieldbuf, field->name);
		if (!strcmp(field->type, "email") || !strcmp(field->type, "tel") || !strcmp(field->type, "text") || !strcmp(field->type, "password") || !strcmp(field->type, "textarea"))
			write_crypt_string(&fieldbuf, field->value_encrypted);
		else
			write_plain_string(&fieldbuf, field->value);
		write_plain_string(&fieldbuf, field->type);
		write_chunk(buffer, &fieldbuf, "AACF");
		free(fieldbuf.bytes);
	}
}

static void write_account_chunk(struct buffer *buffer, struct account *account)
{
	struct buffer accbuf, fieldbuf;
	struct field *field;

	if (account->is_app) {
		write_app_chunk(buffer, account);
		return;
	}

	memset(&accbuf, 0, sizeof(accbuf));
	write_plain_string(&accbuf, account->id);
	write_crypt_string(&accbuf, account->name_encrypted);
	write_crypt_string(&accbuf, account->group_encrypted);
	write_hex_string(&accbuf, account->url);
	write_crypt_string(&accbuf, account->note_encrypted);
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_crypt_string(&accbuf, account->username_encrypted);
	write_crypt_string(&accbuf, account->password_encrypted);
	write_boolean(&accbuf, account->pwprotect);
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_chunk(buffer, &accbuf, "ACCT");
	free(accbuf.bytes);
	list_for_each_entry(field, &account->field_head, list) {
		memset(&fieldbuf, 0, sizeof(fieldbuf));
		write_plain_string(&fieldbuf, field->name);
		write_plain_string(&fieldbuf, field->type);
		if (!strcmp(field->type, "email") || !strcmp(field->type, "tel") || !strcmp(field->type, "text") || !strcmp(field->type, "password") || !strcmp(field->type, "textarea"))
			write_crypt_string(&fieldbuf, field->value_encrypted);
		else
			write_plain_string(&fieldbuf, field->value);
		write_boolean(&fieldbuf, field->checked);
		write_chunk(buffer, &fieldbuf, "ACFL");
		free(fieldbuf.bytes);
	}
}
static void write_share_chunk(struct buffer *buffer, struct share *share)
{
	struct buffer sharebuf = { .bytes = share->chunk, .len = share->chunk_len, .max = share->chunk_len };
	write_chunk(buffer, &sharebuf, "SHAR");
}

size_t blob_write(const struct blob *blob, const unsigned char key[KDF_HASH_LEN], char **out)
{
	struct buffer buffer;
	struct share *last_share = NULL;
	struct account *account;
	UNUSED(key);

	memset(&buffer, 0, sizeof(buffer));

	_cleanup_free_ char *version = xultostr(blob->version);
	buffer_append(&buffer, "LPAV", 4);
	write_plain_string(&buffer, version);
	buffer_append(&buffer, "LOCL", 4);
	write_plain_string(&buffer, LASTPASS_CLI_VERSION);

	list_for_each_entry(account, &blob->account_head, list) {
		if (!account->share)
			write_account_chunk(&buffer, account);
	}
	list_for_each_entry(account, &blob->account_head, list) {
		if (!account->share)
			continue;
		if (last_share != account->share) {
			write_share_chunk(&buffer, account->share);
			last_share = account->share;
		}
		write_account_chunk(&buffer, account);
	}

	*out = buffer.bytes;
	return buffer.len;
}

static struct blob *local_blob(const unsigned char key[KDF_HASH_LEN], const struct private_key *private_key)
{
	_cleanup_free_ unsigned char *blob = NULL;
	size_t len = config_read_encrypted_buffer("blob", &blob, key);
	if (!blob)
		return NULL;
	return blob_parse(blob, len, key, private_key);
}

static struct blob *blob_get_latest(struct session *session, const unsigned char key[KDF_HASH_LEN])
{
	struct blob *local;
	unsigned long long remote_version;

	local = local_blob(key, &session->private_key);
	if (!local)
		return lastpass_get_blob(session, key);
	remote_version = lastpass_get_blob_version(session, key);
	if (remote_version == 0) {
		blob_free(local);
		return NULL;
	}
	if (local->version < remote_version || (local->local_version && local->version == remote_version)) {
		blob_free(local);
		return lastpass_get_blob(session, key);
	}
	config_touch("blob");
	return local;
}

static time_t auto_sync_time(void)
{
	time_t time;
	char *env = getenv("LPASS_AUTO_SYNC_TIME");

	if (!env)
		return 5;
	time = strtoul(env, NULL, 10);
	if (!time)
		return 5;
	return time;
}

struct blob *blob_load(enum blobsync sync, struct session *session, const unsigned char key[KDF_HASH_LEN])
{
	if (sync == BLOB_SYNC_AUTO) {
		if (!config_exists("blob"))
			return blob_get_latest(session, key);
		else if (time(NULL) - config_mtime("blob") <= auto_sync_time())
			return local_blob(key, &session->private_key);
		return blob_get_latest(session, key);
	} else if (sync == BLOB_SYNC_YES)
		return blob_get_latest(session, key);
	else if (sync == BLOB_SYNC_NO)
		return local_blob(key, &session->private_key);

	return NULL;
}
void blob_save(const struct blob *blob, const unsigned char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *bluffer = NULL;
	size_t len;

	len = blob_write(blob, key, &bluffer);
	if (!len)
		die("Could not write blob.");

	config_write_encrypted_buffer("blob", bluffer, len, key);
}

#define set_field(obj, field) do { \
	free(obj->field); \
	obj->field = field; \
} while (0)
#define set_encrypted_field(obj, field) do { \
	if (!obj->field || !field || strcmp(obj->field, field)) { \
		set_field(obj, field); \
		free(obj->field##_encrypted); \
		obj->field##_encrypted = encrypt_and_base64(field, account->share ? account->share->key : key); \
	} \
} while (0)
#define reencrypt_field(obj, field) do { \
	free(obj->field##_encrypted); \
	obj->field##_encrypted = encrypt_and_base64(obj->field, account->share ? account->share->key : key); \
} while (0)

void account_set_username(struct account *account, char *username, unsigned const char key[KDF_HASH_LEN])
{
	set_encrypted_field(account, username);
}
void account_set_password(struct account *account, char *password, unsigned const char key[KDF_HASH_LEN])
{
	set_encrypted_field(account, password);
}
void account_set_group(struct account *account, char *group, unsigned const char key[KDF_HASH_LEN])
{
	set_encrypted_field(account, group);
}
void account_set_name(struct account *account, char *name, unsigned const char key[KDF_HASH_LEN])
{
	set_encrypted_field(account, name);
}
void account_set_note(struct account *account, char *note, unsigned const char key[KDF_HASH_LEN])
{
	set_encrypted_field(account, note);
}
void account_set_url(struct account *account, char *url, unsigned const char key[KDF_HASH_LEN])
{
	UNUSED(key);
	set_field(account, url);
}
void account_set_appname(struct account *account, char *appname, unsigned const char key[KDF_HASH_LEN])
{
	UNUSED(key);
	struct app *app;
	if (!account->is_app)
		return;

	app = account_to_app(account);
	set_field(app, appname);
}
void field_set_value(struct account *account, struct field *field, char *value, unsigned const char key[KDF_HASH_LEN])
{
	if (!strcmp(field->type, "email") || !strcmp(field->type, "tel") || !strcmp(field->type, "text") || !strcmp(field->type, "password") || !strcmp(field->type, "textarea"))
		set_encrypted_field(field, value);
	else
		set_field(field, value);
}

static bool is_shared_folder_name(const char *fullname)
{
	return !strncmp(fullname, "Shared-", 7) && strchr(fullname, '/');
}

void account_reencrypt(struct account *account, const unsigned char key[KDF_HASH_LEN])
{
	struct field *field;

	reencrypt_field(account, name);
	reencrypt_field(account, group);
	reencrypt_field(account, username);
	reencrypt_field(account, password);
	reencrypt_field(account, note);

	list_for_each_entry(field, &account->field_head, list) {
		reencrypt_field(field, value);
	}
}

/*
 * Set just group and name, assuming we've stripped off any leading
 * shared folder from fullname.
 */
static void account_set_group_name(struct account *account,
				   const char *groupname,
				   unsigned const char key[KDF_HASH_LEN])
{
	char *slash = strrchr(groupname, '/');
	if (!slash) {
		account_set_name(account, xstrdup(groupname), key);
		account_set_group(account, xstrdup(""), key);
	} else {
		account_set_name(account, xstrdup(slash + 1), key);
		account_set_group(account, xstrndup(groupname, slash - groupname), key);
	}
}

void account_set_fullname(struct account *account, char *fullname, unsigned const char key[KDF_HASH_LEN])
{
	char *groupname = fullname;

	/* skip Shared-XXX/ for shared folders */
	if (is_shared_folder_name(fullname)) {
		char *tmp = strchr(fullname, '/');
		if (tmp)
			groupname = tmp + 1;
	}
	account_set_group_name(account, groupname, key);
	free(account->fullname);
	account->fullname = fullname;
}

struct share *find_unique_share(struct blob *blob, const char *name)
{
       struct share *share;

       list_for_each_entry(share, &blob->share_head, list) {
               if (!strcasecmp(share->name, name)) {
                       return share;
               }
       }
       return NULL;
}

/*
 * Assign an account to the proper shared folder, if any.
 *
 * If the share changed from whatever it was previously, the account
 * fields are reencrypted with either the share key or the blob key.
 *
 * This function may exit if the name represents a shared folder but
 * same folder is not available.
 */
void account_assign_share(struct blob *blob, struct account *account,
			  unsigned const char key[KDF_HASH_LEN])
{
	struct share *share, *old_share;
	_cleanup_free_ char *shared_name = NULL;
	char *name = account->fullname;

	old_share = account->share;

	/* strip off shared groupname */
	char *slash = strchr(name, '/');
	if (!slash) {
		account->share = NULL;
		goto reencrypt;
	}

	shared_name = xstrndup(name, slash - name);

	/* find a share matching group name */
	share = find_unique_share(blob, shared_name);

	if (!share && is_shared_folder_name(name)) {
		/* don't allow normal folders named like SFs */
		die("Unable to find shared folder for %s in blob\n", name);
	}

	account->share = share;

	/* update group name to not include new share, if needed */
	if (share)
		account_set_group_name(account, slash + 1, key);

reencrypt:
	if (old_share != account->share)
		account_reencrypt(account, key);
}

struct account *notes_expand(struct account *acc)
{
	struct account *expand;
	struct field *field = NULL;
	char *start, *lf, *colon, *name, *value;
	struct attach *attach, *tmp;
	char *line = NULL;
	size_t len;

	if (!account_is_secure_note(acc))
		return NULL;

	expand = new_account();

	expand->id = xstrdup(acc->id);
	expand->pwprotect = acc->pwprotect;
	expand->name = xstrdup(acc->name);
	expand->group = xstrdup(acc->group);
	expand->fullname = xstrdup(acc->fullname);
	expand->share = acc->share;

	if (strncmp(acc->note, "NoteType:", 9))
		return NULL;

	enum note_type note_type = NOTE_TYPE_NONE;
	lf = strchr(acc->note + 9, '\n');
	if (lf) {
		_cleanup_free_ char *type = xstrndup(acc->note + 9, lf - (acc->note + 9));
		note_type = notes_get_type_by_name(type);
	}

	for (start = acc->note; ; ) {
		name = value = NULL;
		lf = strchrnul(start, '\n');
		if (lf == start && !field)
			goto skip;

		line = xstrndup(start, lf - start);
		colon = strchr(line, ':');
		if (colon) {
			name = xstrndup(line, colon - line);
			value = xstrdup(colon + 1);
		}

		/*
		 * Append non-keyed strings to existing field.
		 * If no field, skip.
		 */
		if (!name) {
			if (field)
				xstrappendf(&field->value, "\n%s", line);
			goto skip;
		}

		/*
		 * If this is a known notetype, append any non-existent
		 * keys to the existing field.  For example, Proc-Type
		 * in the ssh private key field goes into private key,
		 * not a Proc-Type field.
		 */
		if (note_type != NOTE_TYPE_NONE &&
		    !note_has_field(note_type, name) && field &&
		    note_field_is_multiline(note_type, field->name)) {
			xstrappendf(&field->value, "\n%s", line);
			goto skip;
		}

		if (!strcmp(name, "Username"))
			expand->username = xstrdup(value);
		else if (!strcmp(name, "Password"))
			expand->password = xstrdup(value);
		else if (!strcmp(name, "URL"))
			expand->url = xstrdup(value);
		else if (!strcmp(name, "Notes")) {
			expand->note = xstrdup(strchr(start, ':') + 1);
			len = strlen(expand->note);
			if (len && expand->note[len - 1] == '\n')
				expand->note[len - 1] = '\0';
			lf = NULL;
		} else {
			field = new0(struct field, 1);
			field->type = xstrdup("text");
			field->name = xstrdup(name);
			field->value = xstrdup(value);
			list_add(&field->list, &expand->field_head);
		}
skip:
		free(value);
		free(name);
		free(line);
		line = NULL;
		if (!lf || !*lf)
			break;
		start = lf + 1;
		if (!*start)
			break;
	}
	if (!expand->note && !expand->username && !expand->url && !expand->password && list_empty(&expand->field_head))
		expand->note = xstrdup(acc->note);
	else if (!expand->note)
		expand->note = xstrdup("");
	if (!expand->url)
		expand->url = xstrdup("");
	if (!expand->username)
		expand->username = xstrdup("");
	if (!expand->password)
		expand->password = xstrdup("");

	/* move attachments to expanded account */
	expand->attachkey = xstrdup(acc->attachkey);
	expand->attachkey_encrypted = xstrdup(acc->attachkey_encrypted);
	expand->attachpresent = acc->attachpresent;

	list_for_each_entry_safe(attach, tmp, &acc->attach_head, list) {
		list_del(&attach->list);
		list_add_tail(&attach->list, &expand->attach_head);
	}

	return expand;
}
struct account *notes_collapse(struct account *acc)
{
	struct account *collapse;
	struct field *field;
	struct attach *attach, *tmp;

	collapse = new_account();

	collapse->id = xstrdup(acc->id);
	collapse->pwprotect = acc->pwprotect;
	collapse->name = xstrdup(acc->name);
	collapse->group = xstrdup(acc->group);
	collapse->fullname = xstrdup(acc->fullname);
	collapse->url = xstrdup("http://sn");
	collapse->username = xstrdup("");
	collapse->password = xstrdup("");
	collapse->note = xstrdup("");
	collapse->share = acc->share;

	/* move attachments back from expanded account */
	collapse->attachkey = xstrdup(acc->attachkey);
	collapse->attachkey_encrypted = xstrdup(acc->attachkey_encrypted);
	collapse->attachpresent = acc->attachpresent;

	list_for_each_entry_safe(attach, tmp, &acc->attach_head, list) {
		list_del(&attach->list);
		list_add_tail(&attach->list, &collapse->attach_head);
	}

	list_for_each_entry(field, &acc->field_head, list) {
		trim(field->value);
		trim(field->name);
		if (!strcmp(field->name, "NoteType"))
			xstrprependf(&collapse->note, "%s:%s\n", field->name, field->value);
		else
			xstrappendf(&collapse->note, "%s:%s\n", field->name, field->value);
	}
	if (strlen(acc->username))
		xstrappendf(&collapse->note, "%s:%s\n", "Username", trim(acc->username));
	if (strlen(acc->password))
		xstrappendf(&collapse->note, "%s:%s\n", "Password", trim(acc->password));
	if (strlen(acc->url))
		xstrappendf(&collapse->note, "%s:%s\n", "URL", trim(acc->url));
	if (strlen(acc->note))
		xstrappendf(&collapse->note, "%s:%s\n", "Notes", trim(acc->note));

	return collapse;
}
