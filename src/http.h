#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdarg.h>

char *http_post_lastpass(const char *page, const char *session, size_t *len, ...);
char *http_post_lastpass_v(const char *page, const char *session, size_t *len, char **argv);

#endif
