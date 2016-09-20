#ifndef XML_H
#define XML_H

#include "session.h"
#include "cipher.h"
#include "list.h"
#include "blob.h"

struct session *xml_ok_session(const char *buf, unsigned const char key[KDF_HASH_LEN]);
char *xml_error_cause(const char *buf, const char *what);
unsigned long long xml_login_check(const char *buf, struct session *session);
int xml_parse_share_getinfo(const char *buf, struct list_head *users);
int xml_parse_share_getpubkey(const char *buf, struct share_user *user);
int xml_parse_pwchange(const char *buf, struct pwchange_info *info);
int xml_api_err(const char *buf);
int xml_parse_share_getpubkeys(const char *buf, struct list_head *user_list);
int xml_parse_share_get_limits(const char *buf, struct share_limit *limit);

#endif
