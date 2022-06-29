#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdarg.h>
#include <curl/curl.h>
#include "session.h"

struct http_param_set
{
	char **argv;
	size_t n_alloced;
};

#define LASTPASS_SERVER	"lastpass.com"

#define HTTP_ERROR_CODE	CURLE_HTTP_RETURNED_ERROR
#define HTTP_ERROR_CONNECT	CURLE_SSL_CONNECT_ERROR

int http_init();
void http_post_add_params(struct http_param_set *params, ...);
char *http_get_lastpass(const char *page, const struct session *session, size_t *len);
char *http_post_lastpass(const char *page, const struct session *session, size_t *len, ...);
char *http_post_lastpass_v(const char *server, const char *page, const struct session *session, size_t *len, char **argv);
char *http_post_lastpass_param_set(const char *page, const struct session *session, size_t *len,
				   struct http_param_set *params);
char *http_post_lastpass_v_noexit(const char *server, const char *page, const struct session *session, size_t *final_len, char **argv, int *curl_ret, long *http_code);

#endif
