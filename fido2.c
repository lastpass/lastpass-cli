/*
 * FIDO2 assertion support for login.
 *
 * Copyright (C) 2026 LastPass CLI contributors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "fido2.h"
#include "password.h"
#include "terminal.h"
#include "util.h"
#include <string.h>

#ifdef HAVE_LIBFIDO2
#include <fido.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ctype.h>
#endif

#ifdef TEST_BUILD
char *fido2_login_credential(const char *assertion_options, const char *origin,
			     char **error)
{
	UNUSED(origin);
	if (getenv("LPASS_TEST_FIDO_ABORT")) {
		if (error)
			*error = xstrdup("Aborted FIDO2 authentication.");
		return NULL;
	}
	if (!assertion_options || !strstr(assertion_options, "challenge")) {
		if (error)
			*error = xstrdup("Could not parse FIDO2 assertion options.");
		return NULL;
	}
	if (error)
		*error = NULL;
	return xstrdup("{\"id\":\"AQID\",\"extensions\":{},\"type\":\"public-key\","
		       "\"rawId\":\"AQID\",\"response\":{\"authenticatorData\":\"AQID\","
		       "\"clientDataJson\":\"AQID\",\"signature\":\"AQID\","
		       "\"userHandle\":null}}");
}
#elif defined(HAVE_LIBFIDO2)

static void fido_dev_freep(fido_dev_t **device)
{
	if (*device)
		fido_dev_free(device);
}

static void fido_assert_freep(fido_assert_t **assertion)
{
	if (*assertion)
		fido_assert_free(assertion);
}

static void fido_dev_info_freep(fido_dev_info_t **devices)
{
	if (*devices)
		fido_dev_info_free(devices, 16);
}

#define _cleanup_fido_dev_free_ _cleanup_(fido_dev_freep)
#define _cleanup_fido_assert_free_ _cleanup_(fido_assert_freep)
#define _cleanup_fido_dev_info_free_ _cleanup_(fido_dev_info_freep)

static char *json_string(const char *start, const char **end)
{
	char *result;
	size_t len = 0;
	const char *p;

	if (*start != '"')
		return NULL;
	for (p = start + 1; *p && *p != '"'; ++p) {
		if (*p == '\\' && p[1])
			++p;
		++len;
	}
	if (*p != '"')
		return NULL;

	result = xcalloc(len + 1, 1);
	for (p = start + 1, len = 0; *p && *p != '"'; ++p) {
		if (*p == '\\') {
			++p;
			switch (*p) {
			case '"': result[len++] = '"'; break;
			case '\\': result[len++] = '\\'; break;
			case '/': result[len++] = '/'; break;
			case 'b': result[len++] = '\b'; break;
			case 'f': result[len++] = '\f'; break;
			case 'n': result[len++] = '\n'; break;
			case 'r': result[len++] = '\r'; break;
			case 't': result[len++] = '\t'; break;
			default:
				free(result);
				return NULL;
			}
		} else {
			result[len++] = *p;
		}
	}
	if (end)
		*end = p + 1;
	return result;
}

static const char *json_skip_space(const char *p)
{
	while (*p && isspace((unsigned char)*p))
		++p;
	return p;
}

static char *json_get_string(const char *json, const char *key)
{
	const char *p = json;

	while (*p) {
		_cleanup_free_ char *name = NULL;
		const char *end;

		if (*p != '"') {
			++p;
			continue;
		}
		name = json_string(p, &end);
		if (!name)
			return NULL;
		p = json_skip_space(end);
		if (*p == ':' && !strcmp(name, key)) {
			p = json_skip_space(p + 1);
			if (*p != '"')
				return NULL;
			return json_string(p, NULL);
		}
	}
	return NULL;
}

static const char *json_array_end(const char *start)
{
	unsigned int depth = 0;
	bool in_string = false;

	for (const char *p = start; *p; ++p) {
		if (in_string) {
			if (*p == '\\' && p[1])
				++p;
			else if (*p == '"')
				in_string = false;
		} else if (*p == '"') {
			in_string = true;
		} else if (*p == '[') {
			++depth;
		} else if (*p == ']' && --depth == 0) {
			return p;
		}
	}
	return NULL;
}

static const char *json_find_key(const char *json, const char *key)
{
	const char *p = json;

	while (*p) {
		_cleanup_free_ char *name = NULL;
		const char *end;

		if (*p != '"') {
			++p;
			continue;
		}
		name = json_string(p, &end);
		if (!name)
			return NULL;
		p = json_skip_space(end);
		if (*p == ':' && !strcmp(name, key))
			return json_skip_space(p + 1);
	}
	return NULL;
}

static size_t base64url_decode(const char *encoded, unsigned char **decoded)
{
	_cleanup_free_ char *standard = NULL;
	size_t len = strlen(encoded), padded_len;
	int decoded_len;
	unsigned int padding = 0;

	if (len % 4 == 1)
		return 0;
	padded_len = (len + 3) & ~(size_t)3;
	standard = xcalloc(padded_len + 1, 1);
	for (size_t i = 0; i < len; ++i) {
		if (encoded[i] == '-')
			standard[i] = '+';
		else if (encoded[i] == '_')
			standard[i] = '/';
		else if (isalnum((unsigned char)encoded[i]) || encoded[i] == '+' || encoded[i] == '/')
			standard[i] = encoded[i];
		else
			return 0;
	}
	while (len + padding < padded_len)
		standard[len + padding++] = '=';

	*decoded = xcalloc(padded_len / 4 * 3 + 1, 1);
	decoded_len = EVP_DecodeBlock(*decoded, (const unsigned char *)standard, (int)padded_len);
	if (decoded_len < 0) {
		free(*decoded);
		*decoded = NULL;
		return 0;
	}
	return (size_t)decoded_len - padding;
}

static char *base64url_encode(const unsigned char *bytes, size_t len)
{
	size_t encoded_len = 4 * ((len + 2) / 3);
	char *encoded = xcalloc(encoded_len + 1, 1);
	int actual_len = EVP_EncodeBlock((unsigned char *)encoded, bytes, (int)len);

	while (actual_len > 0 && encoded[actual_len - 1] == '=')
		--actual_len;
	for (int i = 0; i < actual_len; ++i) {
		if (encoded[i] == '+')
			encoded[i] = '-';
		else if (encoded[i] == '/')
			encoded[i] = '_';
	}
	encoded[actual_len] = '\0';
	return encoded;
}

static bool add_allow_credentials(fido_assert_t *assertion, const char *options,
				  size_t *count)
{
	const char *array = json_find_key(options, "allowCredentials");
	const char *end;
	const char *p;

	if (!array || *array != '[')
		return false;
	end = json_array_end(array);
	if (!end)
		return false;
	for (p = array; p < end;) {
		const char *next;
		_cleanup_free_ char *name = NULL;
		_cleanup_free_ char *id = NULL;
		_cleanup_free_ unsigned char *credential_id = NULL;
		size_t credential_id_len;

		if (*p != '"') {
			++p;
			continue;
		}
		name = json_string(p, &next);
		if (!name)
			return false;
		p = next;
		p = json_skip_space(p);
		if (*p != ':')
			continue;
		if (strcmp(name, "id"))
			continue;
		p = json_skip_space(p + 1);
		if (*p != '"')
			return false;
		id = json_string(p, &next);
		if (!id)
			return false;
		credential_id_len = base64url_decode(id, &credential_id);
		if (!credential_id_len || fido_assert_allow_cred(assertion,
								 credential_id,
								 credential_id_len) != FIDO_OK)
			return false;
		++*count;
		p = next;
	}
	return *count > 0;
}

static char *assertion_for_device(const char *path, fido_assert_t *assertion,
				 fido_opt_t uv_option,
				 char **error)
{
	_cleanup_fido_dev_free_ fido_dev_t *device = NULL;
	_cleanup_free_ char *pin = NULL;
	const char *retry_message = NULL;
	bool pin_required = false;
	int result;

	device = fido_dev_new();
	if (!device || fido_dev_open(device, path) != FIDO_OK) {
		if (error)
			*error = xstrdup("Could not open the FIDO2 authenticator.");
		return NULL;
	}

	if (fido_assert_set_up(assertion, FIDO_OPT_TRUE) != FIDO_OK ||
	    fido_assert_set_uv(assertion, uv_option) != FIDO_OK ||
	    fido_assert_set_count(assertion, 1) != FIDO_OK) {
		if (error)
			*error = xstrdup("Could not configure the FIDO2 assertion.");
		return NULL;
	}
	for (;;) {
		if (pin_required) {
			free(pin);
			pin = password_prompt("YubiKey PIN", retry_message,
					      "Please enter your FIDO2 authenticator PIN.");
			if (!pin) {
				if (error)
					*error = xstrdup("Aborted FIDO2 authentication.");
				return NULL;
			}
		}

		terminal_fprintf(stderr, TERMINAL_FG_YELLOW TERMINAL_BOLD
				 "Touch your FIDO2 authenticator to complete authentication."
				 TERMINAL_RESET "\n");
		result = fido_dev_get_assert(device, assertion,
					     pin_required ? pin : NULL);
		if (pin)
			secure_clear(pin, strlen(pin));
		if (result == FIDO_OK)
			break;
		if (!pin_required && result == FIDO_ERR_PIN_REQUIRED) {
			pin_required = true;
			retry_message = NULL;
			continue;
		}
		if (!pin_required || (result != FIDO_ERR_PIN_INVALID &&
				      result != FIDO_ERR_PIN_AUTH_INVALID)) {
			if (error)
				xasprintf(error, "FIDO2 authentication failed: %s.",
					  fido_strerr(result));
			return NULL;
		}
		retry_message = "Invalid YubiKey PIN; please try again.";
	}

	return xstrdup("ok");
}

char *fido2_login_credential(const char *assertion_options, const char *origin,
			     char **error)
{
	_cleanup_free_ char *challenge = NULL;
	_cleanup_free_ char *rp_id = NULL;
	_cleanup_free_ char *verification = NULL;
	_cleanup_free_ char *client_data = NULL;
	_cleanup_free_ char *credential = NULL;
	_cleanup_free_ char *credential_id = NULL;
	_cleanup_free_ char *authenticator_data = NULL;
	_cleanup_free_ char *signature = NULL;
	_cleanup_free_ char *user_handle = NULL;
	_cleanup_free_ char *client_data_encoded = NULL;
	_cleanup_free_ char *device_prompt = NULL;
	_cleanup_free_ unsigned char *client_data_hash = NULL;
	_cleanup_free_ unsigned char *assertion_challenge = NULL;
	_cleanup_fido_dev_info_free_ fido_dev_info_t *devices = NULL;
	_cleanup_fido_assert_free_ fido_assert_t *assertion = NULL;
	const char *server_origin;
	size_t challenge_len, n_devices = 0, n_credentials = 0;
	fido_opt_t uv_required;
	char *result;

	if (error)
		*error = NULL;
	challenge = json_get_string(assertion_options, "challenge");
	rp_id = json_get_string(assertion_options, "rpId");
	verification = json_get_string(assertion_options, "userVerification");
	if (!challenge || !rp_id || !verification) {
		if (error)
			*error = xstrdup("Could not parse FIDO2 assertion options.");
		return NULL;
	}
	if (!strcmp(rp_id, "lastpass.com"))
		server_origin = "https://lastpass.com";
	else if (!strcmp(rp_id, "lastpass.eu"))
		server_origin = "https://lastpass.eu";
	else {
		if (error)
			*error = xstrdup("The FIDO2 relying party is not a LastPass server.");
		return NULL;
	}
	if (origin && strcmp(origin, server_origin)) {
		if (error)
			*error = xstrdup("FIDO2 origin does not match the login server.");
		return NULL;
	}
	challenge_len = base64url_decode(challenge, &assertion_challenge);
	if (!challenge_len) {
		if (error)
			*error = xstrdup("The FIDO2 challenge is malformed.");
		return NULL;
	}

	/* The service's browser client sends clientDataJSON with these fields. */
	xasprintf(&client_data,
		  "{\"type\":\"webauthn.get\",\"challenge\":\"%s\",\"origin\":\"%s\",\"crossOrigin\":false}",
		  challenge, server_origin);
	client_data_hash = xmalloc(SHA256_DIGEST_LENGTH);
	SHA256((const unsigned char *)client_data, strlen(client_data), client_data_hash);
	client_data_encoded = base64url_encode((const unsigned char *)client_data,
						 strlen(client_data));

	assertion = fido_assert_new();
	if (!assertion || fido_assert_set_rp(assertion, rp_id) != FIDO_OK ||
	    fido_assert_set_clientdata_hash(assertion, client_data_hash,
					    SHA256_DIGEST_LENGTH) != FIDO_OK ||
	    !add_allow_credentials(assertion, assertion_options, &n_credentials)) {
		if (error)
			*error = xstrdup("Could not prepare the FIDO2 assertion.");
		return NULL;
	}
	if (!strcmp(verification, "required"))
		uv_required = FIDO_OPT_TRUE;
	else if (!strcmp(verification, "discouraged"))
		uv_required = FIDO_OPT_FALSE;
	else
		uv_required = FIDO_OPT_OMIT;

	fido_init(0);
	for (;;) {
		int result;

		devices = fido_dev_info_new(16);
		if (!devices) {
			if (error)
				*error = xstrdup("Could not enumerate FIDO2 authenticators.");
			return NULL;
		}
		result = fido_dev_info_manifest(devices, 16, &n_devices);
		if (result != FIDO_OK) {
			if (error)
				xasprintf(error, "Could not enumerate FIDO2 authenticators: %s.",
					  fido_strerr(result));
			return NULL;
		}
		if (n_devices)
			break;

		fido_dev_info_free(&devices, 16);
		free(device_prompt);
		device_prompt = password_prompt("Insert FIDO2 authenticator", NULL,
			"Insert your FIDO2 authenticator and press Enter to continue. "
			"Cancel to abort login.");
		if (!device_prompt) {
			if (error)
				*error = xstrdup("Aborted FIDO2 authentication.");
			return NULL;
		}
	}

	{
		const fido_dev_info_t *info = fido_dev_info_ptr(devices, 0);
		_cleanup_free_ char *device_error = NULL;
		_cleanup_free_ char *result = assertion_for_device(
			fido_dev_info_path(info), assertion, uv_required,
			&device_error);
		if (!result) {
			if (error)
				*error = device_error ? xstrdup(device_error) :
					xstrdup("FIDO2 authentication failed.");
			return NULL;
		}
	}
	credential_id = base64url_encode(fido_assert_id_ptr(assertion, 0),
					 fido_assert_id_len(assertion, 0));
	authenticator_data = base64url_encode(fido_assert_authdata_raw_ptr(assertion, 0),
					      fido_assert_authdata_raw_len(assertion, 0));
	signature = base64url_encode(fido_assert_sig_ptr(assertion, 0),
				      fido_assert_sig_len(assertion, 0));
	if (fido_assert_user_id_ptr(assertion, 0) &&
	    fido_assert_user_id_len(assertion, 0))
		user_handle = base64url_encode(fido_assert_user_id_ptr(assertion, 0),
					       fido_assert_user_id_len(assertion, 0));
	else
		user_handle = xstrdup("");

	if (*user_handle)
		xasprintf(&credential,
			  "{\"id\":\"%s\",\"extensions\":{},\"type\":\"public-key\","
			  "\"rawId\":\"%s\",\"response\":{\"authenticatorData\":\"%s\","
			  "\"clientDataJson\":\"%s\",\"signature\":\"%s\","
			  "\"userHandle\":\"%s\"}}",
			  credential_id, credential_id, authenticator_data,
			  client_data_encoded, signature, user_handle);
	else
		xasprintf(&credential,
			  "{\"id\":\"%s\",\"extensions\":{},\"type\":\"public-key\","
			  "\"rawId\":\"%s\",\"response\":{\"authenticatorData\":\"%s\","
			  "\"clientDataJson\":\"%s\",\"signature\":\"%s\","
			  "\"userHandle\":null}}",
			  credential_id, credential_id, authenticator_data,
			  client_data_encoded, signature);
	result = credential;
	credential = NULL;
	return result;
}

#else
char *fido2_login_credential(const char *assertion_options, const char *origin,
			     char **error)
{
	UNUSED(assertion_options);
	UNUSED(origin);
	if (error)
		*error = xstrdup("FIDO2 login support was not built (libfido2 is unavailable).");
	return NULL;
}
#endif
