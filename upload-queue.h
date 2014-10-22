#ifndef UPLOADQUEUE_H
#define UPLOADQUEUE_H

#include "kdf.h"
#include "session.h"
#include "blob.h"
#include <stdbool.h>

void upload_queue_enqueue(enum blobsync sync, unsigned const char key[KDF_HASH_LEN], const struct session *session, const char *page, ...);
bool upload_queue_is_running(void);
void upload_queue_kill(void);
void upload_queue_ensure_running(unsigned const char key[KDF_HASH_LEN], const struct session *session);

#endif
