#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdarg.h>

struct http_param_set
{
	char **argv;
	size_t n_alloced;
};

void http_post_add_params(struct http_param_set *params, ...);
char *http_post_lastpass(const char *page, const char *session, size_t *len, ...);
char *http_post_lastpass_v(const char *page, const char *session, size_t *len, char **argv);
char *http_post_lastpass_param_set(const char *page, const char *session, size_t *len,
				   struct http_param_set *params);
char *http_post_lastpass_v_noexit(const char *page, const char *session, size_t *final_len, char **argv, int *curl_ret, long *http_code);

#endif
