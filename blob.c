/*
 * Copyright (c) 2014-2015 LastPass.
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

void share_free(struct share *share)
{
	if (!share)
		return;
	if (--share->refcount > 0)
		return;

	free(share->name);
	free(share->id);
	free(share->chunk);
	free(share);
}

void share_assign(struct share *share, struct share **ptr)
{
	if (!share) {
		*ptr = NULL;
		return;
	}
	++share->refcount;
	*ptr = share;
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

void account_free(struct account *account)
{
	if (!account)
		return;

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
	for (struct field *field = account->field_head, *next_field = NULL; field; field = next_field) {
		next_field = field->next;
		field_free(field);
	}
	share_free(account->share);
	free(account);
}

void blob_free(struct blob *blob)
{
	if (!blob)
		return;

	for (struct account *account = blob->account_head, *next_account = NULL; account; account = next_account) {
		next_account = account->next;
		account_free(account);
	}
	free(blob);
}

struct blob_pos {
	const char *data;
	size_t len;
};

struct chunk {
	char name[4 + 1];
	const char *data;
	size_t len;
};

struct item {
	const char *data;
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

	result = hex_to_bytes(item.data, &str);
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

	return xstrndup(item.data, item.len);
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

#define entry_plain(var) do { \
	char *__entry_val__ = read_plain_string(chunk); \
	if (!__entry_val__) \
		goto error; \
	parsed->var = __entry_val__; \
	} while (0)
#define entry_hex(var) do { \
	char *__entry_val__ = read_hex_string(chunk); \
	if (!__entry_val__) \
		goto error; \
	parsed->var = __entry_val__; \
	} while (0)
#define entry_boolean(var) do { \
	int __entry_val__ = read_boolean(chunk); \
	if (__entry_val__ < 0) \
		goto error; \
	parsed->var = __entry_val__; \
	} while (0)
#define entry_crypt(var) do { \
	char *__entry_val__ = read_crypt_string(chunk, key, &parsed->var##_encrypted); \
	if (!__entry_val__) \
		goto error; \
	parsed->var = __entry_val__; \
	} while (0)
#define skip(placeholder) do { \
	struct item skip_item; \
	if (!read_item(chunk, &skip_item)) \
		goto error; \
	} while (0)

static struct account *account_parse(struct chunk *chunk, const unsigned char key[KDF_HASH_LEN])
{
	struct account *parsed = new0(struct account, 1);

	entry_plain(id);
	entry_crypt(name);
	entry_crypt(group);
	entry_hex(url);
	entry_crypt(note);
	skip(fav);
	skip(sharedfromaid);
	entry_crypt(username);
	entry_crypt(password);
	entry_boolean(pwprotect);
	skip(genpw);
	skip(sn);
	skip(last_touch);
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
	skip(attachkey);
	skip(attachpresent);
	skip(individualshare);
	skip(notetype);
	skip(noalert);
	skip(last_modified_gmt);
	skip(hasbeenshared);
	skip(last_pwchange_gmt);
	skip(created_gmt);
	skip(vulnerable);

	if (parsed->name[0] == 16)
		parsed->name[0] = '\0';
	if (parsed->group[0] == 16)
		parsed->group[0] = '\0';
	if (strlen(parsed->name) && strlen(parsed->group))
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

static struct share *share_parse(struct chunk *chunk, const struct private_key *private_key)
{
	struct share *parsed = new0(struct share, 1);
	struct item item;
	_cleanup_free_ char *ciphertext = NULL;
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
	hex_to_bytes(item.data, &ciphertext);
	hex_key = cipher_rsa_decrypt(ciphertext, item.len / 2, private_key);
	if (!hex_key)
		goto error;
	len = strlen(hex_key);
	if (len % 2 != 0)
		goto error;
	len /= 2;
	if (len != KDF_HASH_LEN)
		goto error;
	hex_to_bytes(hex_key, (char **)&key);
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

#undef entry_plain
#undef entry_hex
#undef entry_boolean
#undef entry_crypt
#undef skip

struct blob *blob_parse(const char *blob, size_t len, const unsigned char key[KDF_HASH_LEN], const struct private_key *private_key)
{
	struct blob_pos blob_pos = { .data = blob, .len = len };
	struct chunk chunk;
	struct account *account, **next_account;
	struct field *field, **next_field = NULL;
	struct share *last_share = NULL;
	struct blob *parsed;
	_cleanup_free_ char *versionstr = NULL;

	parsed = new0(struct blob, 1);
	parsed->local_version = false;
	next_account = &parsed->account_head;

	while (read_chunk(&blob_pos, &chunk)) {
		if (!strcmp(chunk.name, "LPAV")) {
			versionstr = xstrndup(chunk.data, chunk.len);
			parsed->version = strtoull(versionstr, NULL, 10);
		} else if (!strcmp(chunk.name, "ACCT")) {
			account = account_parse(&chunk, last_share ? last_share->key : key);
			if (!account)
				goto error;
			share_assign(last_share, &account->share);

			*next_account = account;
			next_account = &account->next;

			next_field = &account->field_head;
		} else if (!strcmp(chunk.name, "ACFL") || !strcmp(chunk.name, "ACOF")) {
			if (!next_field)
				goto error;

			field = field_parse(&chunk, last_share ? last_share->key : key);
			if (!field)
				goto error;

			*next_field = field;
			next_field = &field->next;
		} else if (!strcmp(chunk.name, "LOCL"))
			parsed->local_version = true;
		else if (!strcmp(chunk.name, "SHAR")) {
			share_free(last_share);
			share_assign(share_parse(&chunk, private_key), &last_share);
		}
	}

	if (!versionstr)
		goto error;
	if (!parsed->account_head)
		goto error;
	share_free(last_share);
	return parsed;

error:
	share_free(last_share);
	blob_free(parsed);
	return NULL;
}

struct buffer {
	size_t len;
	size_t max;
	char *bytes;
};

static void buffer_append(struct buffer *buffer, void *bytes, size_t len)
{
	if (buffer->len + len > buffer->max) {
		buffer->max = buffer->len + len + 512;
		buffer->bytes = xrealloc(buffer->bytes, buffer->max);
	}
	memcpy(buffer->bytes + buffer->len, bytes, len);
	buffer->len += len;
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
	bytes_to_hex(bytes, &hex, strlen(bytes));
	write_plain_string(buffer, hex);
}
static void write_crypt_string(struct buffer *buffer, char *bytes, const unsigned char key[KDF_HASH_LEN])
{
	_cleanup_free_ char *encrypted = NULL;
	size_t len;

	len = cipher_aes_encrypt(bytes, key, &encrypted);
	if (!encrypted)
		die("Could not write encrypted string.");
	write_item(buffer, encrypted, len);
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

static void write_account_chunk(struct buffer *buffer, struct account *account, const unsigned char key[KDF_HASH_LEN])
{
	struct buffer accbuf, fieldbuf;

	memset(&accbuf, 0, sizeof(accbuf));
	write_plain_string(&accbuf, account->id);
	write_crypt_string(&accbuf, account->name, key);
	write_crypt_string(&accbuf, account->group, key);
	write_hex_string(&accbuf, account->url);
	write_crypt_string(&accbuf, account->note, key);
	write_plain_string(&accbuf, "skipped");
	write_plain_string(&accbuf, "skipped");
	write_crypt_string(&accbuf, account->username, key);
	write_crypt_string(&accbuf, account->password, key);
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
	for (struct field *field = account->field_head; field; field = field->next) {
		memset(&fieldbuf, 0, sizeof(fieldbuf));
		write_plain_string(&fieldbuf, field->name);
		write_plain_string(&fieldbuf, field->type);
		if (!strcmp(field->type, "email") || !strcmp(field->type, "tel") || !strcmp(field->type, "text") || !strcmp(field->type, "password") || !strcmp(field->type, "textarea"))
			write_crypt_string(&fieldbuf, field->value, key);
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
	_cleanup_free_ char *version;

	memset(&buffer, 0, sizeof(buffer));

	version = xultostr(blob->version);
	buffer_append(&buffer, "LPAV", 4);
	write_plain_string(&buffer, version);
	buffer_append(&buffer, "LOCL", 4);
	write_plain_string(&buffer, LASTPASS_CLI_VERSION);

	for (struct account *account = blob->account_head; account; account = account->next) {
		if (!account->share)
			write_account_chunk(&buffer, account, key);
	}
	for (struct account *account = blob->account_head; account; account = account->next) {
		if (!account->share)
			continue;
		if (last_share != account->share) {
			write_share_chunk(&buffer, account->share);
			last_share = account->share;
		}
		write_account_chunk(&buffer, account, account->share->key);
	}

	*out = buffer.bytes;
	return buffer.len;
}

static struct blob *local_blob(const unsigned char key[KDF_HASH_LEN], const struct private_key *private_key)
{
	_cleanup_free_ char *blob = NULL;
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

static char *encrypt_and_base64(const char *str, unsigned const char key[KDF_HASH_LEN])
{
	char *intermediate = NULL;
	char *base64 = NULL;
	size_t len;

	base64 = trim(xstrdup(str));
	len = cipher_aes_encrypt(base64, key, &intermediate);
	free(base64);
	base64 = cipher_base64(intermediate, len);
	free(intermediate);
	return base64;
}

#define set_field(obj, field) do { \
	free(obj->field); \
	obj->field = field; \
} while (0)
#define set_encrypted_field(obj, field) do { \
	set_field(obj, field); \
	free(obj->field##_encrypted); \
	obj->field##_encrypted = encrypt_and_base64(field, account->share ? account->share->key : key); \
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
void field_set_value(struct account *account, struct field *field, char *value, unsigned const char key[KDF_HASH_LEN])
{
	if (!strcmp(field->type, "email") || !strcmp(field->type, "tel") || !strcmp(field->type, "text") || !strcmp(field->type, "password") || !strcmp(field->type, "textarea"))
		set_encrypted_field(field, value);
	else
		set_field(field, value);
}
void account_set_fullname(struct account *account, char *fullname, unsigned const char key[KDF_HASH_LEN])
{
	char *slash = strrchr(fullname, '/');
	if (!slash) {
		account_set_name(account, xstrdup(fullname), key);
		account_set_group(account, xstrdup(""), key);
	} else {
		account_set_name(account, xstrdup(slash + 1), key);
		account_set_group(account, xstrndup(fullname, slash - fullname), key);
	}
	free(account->fullname);
	account->fullname = fullname;
}

struct account *notes_expand(struct account *acc)
{
	struct account *expand;
	struct field *field;
	char *start, *lf, *colon, *name, *value;
	char *line = NULL;
	size_t len;

	if (strcmp(acc->url, "http://sn"))
		return NULL;

	expand = new0(struct account, 1);

	expand->id = xstrdup(acc->id);
	expand->pwprotect = acc->pwprotect;
	expand->name = xstrdup(acc->name);
	expand->group = xstrdup(acc->group);
	expand->fullname = xstrdup(acc->fullname);
	share_assign(acc->share, &expand->share);

	if (strncmp(acc->note, "NoteType:", 9))
		return NULL;

	for (start = acc->note; ; ) {
		lf = strchrnul(start, '\n');
		if (lf - start < 0)
			lf = NULL;
		if (lf - start <= 0)
			goto skip;
		line = xstrndup(start, lf - start);
		colon = strchr(line, ':');
		if (!colon)
			goto skip;
		*colon = '\0';
		name = line;
		value = colon + 1;
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
			field->next = expand->field_head;
			expand->field_head = field;
		}
skip:
		free(line);
		line = NULL;
		if (!lf || !*lf)
			break;
		start = lf + 1;
		if (!*start)
			break;
	}
	if (!expand->note && !expand->username && !expand->url && !expand->password && !expand->field_head)
		expand->note = xstrdup(acc->note);
	else if (!expand->note)
		expand->note = xstrdup("");
	if (!expand->url)
		expand->url = xstrdup("");
	if (!expand->username)
		expand->username = xstrdup("");
	if (!expand->password)
		expand->password = xstrdup("");

	return expand;
}
struct account *notes_collapse(struct account *acc)
{
	struct account *collapse;

	collapse = new0(struct account, 1);

	collapse->id = xstrdup(acc->id);
	collapse->pwprotect = acc->pwprotect;
	collapse->name = xstrdup(acc->name);
	collapse->group = xstrdup(acc->group);
	collapse->fullname = xstrdup(acc->fullname);
	collapse->url = xstrdup("http://sn");
	collapse->username = xstrdup("");
	collapse->password = xstrdup("");
	collapse->note = xstrdup("");
	share_assign(acc->share, &collapse->share);

	for (struct field *field = acc->field_head; field; field = field->next) {
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
