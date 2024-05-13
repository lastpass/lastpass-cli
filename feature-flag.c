/*
 * feature flag handling routines
 *
 * Copyright (C) 2024 LastPass.
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
#include "xml.h"
#include "util.h"
#include "config.h"
#include <string.h>

#define SESSION_FF_URL_ENCRYPTION "session_ff_url_encryption"
#define SESSION_FF_URL_LOGGING "session_ff_url_logging"

void feature_flag_load_xml_attr(struct feature_flag *feature_flag, xmlDoc *doc, xmlAttrPtr attr) {
    if (!xmlStrcmp(attr->name, BAD_CAST "url_encryption")) {
        feature_flag->url_encryption_enabled = !strcmp((char *)xmlNodeListGetString(doc, attr->children, 1), "1");
    }

    if (!xmlStrcmp(attr->name, BAD_CAST "url_logging")) {
        feature_flag->url_logging_enabled = !strcmp((char *)xmlNodeListGetString(doc, attr->children, 1), "1");
    }
}

void feature_flag_save(const struct feature_flag *feature_flag, unsigned const char key[KDF_HASH_LEN]) {
    config_write_encrypted_string(SESSION_FF_URL_ENCRYPTION, feature_flag->url_encryption_enabled ? "1" : "0", key);
    config_write_encrypted_string(SESSION_FF_URL_LOGGING, feature_flag->url_logging_enabled ? "1" : "0", key);
}

void feature_flag_load(struct feature_flag *feature_flag, unsigned const char key[KDF_HASH_LEN]) {
    char *ff_url_encryption = config_read_encrypted_string(SESSION_FF_URL_ENCRYPTION, key);
    if (ff_url_encryption != NULL) {
        feature_flag->url_encryption_enabled = !strcmp(ff_url_encryption, "1");
    }

    char *ff_url_logging = config_read_encrypted_string(SESSION_FF_URL_LOGGING, key);
    if (ff_url_logging != NULL) {
        feature_flag->url_logging_enabled = !strcmp(ff_url_logging, "1");
    }
}

void feature_flag_cleanup() {
    config_unlink(SESSION_FF_URL_ENCRYPTION);
    config_unlink(SESSION_FF_URL_LOGGING);
}
