#ifndef UPLOADQUEUE_H
#define UPLOADQUEUE_H

#include "lastpass/kdf.h"
#include "lastpass/session.h"
#include "lastpass/blob.h"
#include "lastpass/http.h"
#include <stdbool.h>

void upload_queue_enqueue(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const char *page, struct http_param_set *params);
bool upload_queue_is_running(void);
void upload_queue_kill(void);
void upload_queue_ensure_running(unsigned const char key[KDF_HASH_LEN], const struct session *session);

#endif
