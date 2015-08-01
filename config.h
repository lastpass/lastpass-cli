#ifndef CONFIG_H
#define CONFIG_H

#include "kdf.h"
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

char *config_path(const char *name);
FILE *config_fopen(const char *name, const char *mode);
bool config_exists(const char *name);
bool config_unlink(const char *name);
time_t config_mtime(const char *name);
void config_touch(const char *name);

void config_write_string(const char *name, const char *string);
void config_write_buffer(const char *name, const char *buffer, size_t len);
char *config_read_string(const char *name);
size_t config_read_buffer(const char *name, unsigned char **buffer);

void config_write_encrypted_string(const char *name, const char *string, unsigned const char key[KDF_HASH_LEN]);
void config_write_encrypted_buffer(const char *name, const char *buffer, size_t len, unsigned const char key[KDF_HASH_LEN]);
char *config_read_encrypted_string(const char *name, unsigned const char key[KDF_HASH_LEN]);
size_t config_read_encrypted_buffer(const char *name, unsigned char **buffer, unsigned const char key[KDF_HASH_LEN]);


#endif
