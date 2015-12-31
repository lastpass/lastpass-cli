/*
 * http posting routines
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
#include "http.h"
#include "util.h"
#include "version.h"
#include "certificate.h"
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <curl/curl.h>

struct mem_chunk {
	char *ptr;
	size_t len;
};

static bool interrupted = false;
static sig_t previous_handler = SIG_DFL;
static void interruption_detected(int signal)
{
	UNUSED(signal);
	interrupted = true;
}
static void set_interrupt_detect(void)
{
	interrupted = false;
	previous_handler = signal(SIGINT, interruption_detected);
}
static void unset_interrupt_detect(void)
{
	interrupted = false;
	signal(SIGINT, previous_handler);
}
static int check_interruption(void *p, double dltotal, double dlnow, double ultotal, double ulnow)
{
	UNUSED(p);
	UNUSED(dltotal);
	UNUSED(dlnow);
	UNUSED(ultotal);
	UNUSED(ulnow);
	return interrupted;
}

static size_t write_data(char *ptr, size_t size, size_t nmemb, void *data)
{
	size_t len, new_len;
	struct mem_chunk *mem = (struct mem_chunk *)data;
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) && nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return 0;
	}
	len = size * nmemb;
	new_len = len + mem->len + 1;
	if (new_len <= mem->len || new_len <= len || new_len < 1) {
		errno = ENOMEM;
		return 0;
	}

	mem->ptr = xrealloc(mem->ptr, new_len);
	memcpy(mem->ptr + mem->len, ptr, len);
	mem->len += len;
	mem->ptr[mem->len] = '\0';

	return len;
}

static CURLcode pin_certificate(CURL *curl, void *sslctx, void *parm)
{
	UNUSED(curl);
	UNUSED(parm);
	X509_STORE *store;
	X509 *cert = NULL;
	BIO *bio = NULL;
	CURLcode ret = CURLE_SSL_CACERT;

	store = X509_STORE_new();
	if (!store)
		goto out;

	bio = BIO_new_mem_buf(CERTIFICATE_THAWTE, -1);
	while ((cert = PEM_read_bio_X509(bio, NULL, 0, NULL))) {
		if (!X509_STORE_add_cert(store, cert)) {
			X509_free(cert);
			goto out;
		}
		X509_free(cert);
	}
	SSL_CTX_set_cert_store((SSL_CTX *)sslctx, store);
	ret = CURLE_OK;
out:
	BIO_free(bio);
	return ret;
}

static
void vhttp_post_add_params(struct http_param_set *param_set, va_list args)
{
	char **argv_ptr;
	char *arg;
	size_t count = 0;

	if (!param_set->argv) {
		param_set->n_alloced = 2;
		param_set->argv = xcalloc(param_set->n_alloced, sizeof(char *));
	}
	argv_ptr = param_set->argv;
	while (*argv_ptr) {
		argv_ptr++;
		count++;
	}

	while ((arg = va_arg(args, char *))) {
		if (count == param_set->n_alloced - 1) {
			param_set->n_alloced += 2;
			param_set->argv = xreallocarray(param_set->argv,
				param_set->n_alloced, sizeof(char *));
			argv_ptr = &param_set->argv[count];
		}
		*argv_ptr++ = arg;
		count++;
	}
	*argv_ptr = 0;
}

void http_post_add_params(struct http_param_set *param_set, ...)
{
	va_list args;
	va_start(args, param_set);
	vhttp_post_add_params(param_set, args);
	va_end(args);
}

char *http_post_lastpass(const char *page, const char *session, size_t *final_len, ...)
{
	va_list args;
	struct http_param_set params = {
		.argv = NULL,
		.n_alloced = 0
	};

	va_start(args, final_len);
	vhttp_post_add_params(&params, args);
	char *result = http_post_lastpass_param_set(page, session, final_len, &params);
	free(params.argv);
	return result;
}

char *http_post_lastpass_v_noexit(const char *page, const char *session, size_t *final_len, char **argv, int *curl_ret, long *http_code)
{
	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *postdata = NULL;
	_cleanup_free_ char *cookie = NULL;
	char *param, *encoded_param;
	CURL *curl = NULL;
	char separator;
	size_t len, new_len;
	int ret;
	struct mem_chunk result;

	xasprintf(&url, "https://lastpass.com/%s", page);

	curl = curl_easy_init();
	if (!curl)
		die("Could not init curl");

	len = 0;
	for (separator = '=', param = *argv;
	     param;
	     separator = (separator == '=') ? '&' : '=', param = *(++argv)) {
		encoded_param = curl_easy_escape(curl, param, 0);
		if (!encoded_param)
			die("Could not escape %s with curl", param);
		new_len = strlen(encoded_param) + 1 /* separator */;
		postdata = xrealloc(postdata, len + new_len + 1 /* null */);
		snprintf(postdata + len, new_len + 1, "%s%c", encoded_param, separator);
		len += new_len;
		curl_free(encoded_param);
	}
	if (len && postdata)
		postdata[len - 1] = '\0';

	memset(&result, 0, sizeof(result));
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, LASTPASS_CLI_USERAGENT);
#if defined(DO_NOT_ENABLE_ME_MITM_PROXY_FOR_DEBUGGING_ONLY)
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_PROXY, "http://localhost:8080");
#else
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
	curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, pin_certificate);
#endif
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, check_interruption);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
	if (postdata)
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
	if (session) {
		xasprintf(&cookie, "PHPSESSID=%s", session);
		curl_easy_setopt(curl, CURLOPT_COOKIE, cookie);
	}

	set_interrupt_detect();
	ret = curl_easy_perform(curl);
	unset_interrupt_detect();

	curl_easy_cleanup(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
	*curl_ret = ret;

	if (ret != CURLE_OK) {
		result.len = 0;
		free(result.ptr);
		result.ptr = NULL;
	} else if (!result.ptr)
		result.ptr = xstrdup("");
	if (final_len)
		*final_len = result.len;

	return result.ptr;
}

char *http_post_lastpass_v(const char *page, const char *session, size_t *final_len, char **argv)
{
	char *result;
	int ret;
	long http_code;

	result = http_post_lastpass_v_noexit(page, session, final_len,
					     argv, &ret, &http_code);

	if (ret != CURLE_OK && ret != CURLE_ABORTED_BY_CALLBACK)
		die("%s.", curl_easy_strerror(ret));

	return result;
}


char *http_post_lastpass_param_set(const char *page, const char *session, size_t *final_len, struct http_param_set *param_set) {
	return http_post_lastpass_v(page, session, final_len, param_set->argv);
}
