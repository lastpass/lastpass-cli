#ifndef XML_H
#define XML_H

#include "session.h"
#include "cipher.h"

struct session *xml_ok_session(const char *buf, unsigned const char key[KDF_HASH_LEN]);
char *xml_error_cause(const char *buf, const char *what);
unsigned long long xml_login_check(const char *buf, struct session *session);

#endif
