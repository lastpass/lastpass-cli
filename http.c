/*
 * Copyright (c) 2014 LastPass.
 *
 *
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

char *http_post_lastpass(const char *page, const char *session, size_t *final_len, ...)
{
	va_list params;
	_cleanup_free_ char **argv = NULL;
	char **argv_ptr;
	int count = 0;

	va_start(params, final_len);
	while (va_arg(params, char *))
		++count;
	va_end(params);

	argv_ptr = argv = xcalloc(count + 1, sizeof(char **));
	va_start(params, final_len);
	while ((*(argv_ptr++) = va_arg(params, char *)));
	va_end(params);

	return http_post_lastpass_v(page, session, final_len, argv);
}
char *http_post_lastpass_v(const char *page, const char *session, size_t *final_len, char **argv)
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
	if (ret != CURLE_OK) {
		result.len = 0;
		free(result.ptr);
		result.ptr = NULL;
		if (ret != CURLE_ABORTED_BY_CALLBACK)
			die("%s.", curl_easy_strerror(ret));
	} else if (!result.ptr)
		result.ptr = xstrdup("");
	if (final_len)
		*final_len = result.len;
	return result.ptr;
}
