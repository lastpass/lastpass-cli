/*
 * command to show the password history of a vault entry
 *
 * Copyright (C) 2014-2018 LastPass.
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
#include "cmd.h"
#include "cipher.h"
#include "util.h"
#include "terminal.h"
#include "kdf.h"
#include "endpoints.h"
#include "clipboard.h"
#include "format.h"
#include "tiny-json.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifndef JSON_POOL_SIZE
#define JSON_POOL_SIZE 1024
#endif

static void print_header(char *title_format, struct account *found) {
    struct buffer buf;

    buffer_init(&buf);
    format_account(&buf, title_format, found);
    terminal_printf("%s\n", buf.bytes);
    free(buf.bytes);
}

static void print_field(char *field_format, struct account *account,
                        char *name, char *value) {
    struct buffer buf;

    buffer_init(&buf);
    format_field(&buf, field_format, account, name, value);
    terminal_printf("%s\n", buf.bytes);
    free(buf.bytes);
}

int cmd_history(int argc, char **argv) {
    unsigned char key[KDF_HASH_LEN];
    struct session *session = NULL;
    struct blob *blob = NULL;
    json_t pool[JSON_POOL_SIZE];
    static struct option long_options[] = {
            {"clip",         no_argument,       NULL, 'c'},
            {"color",        required_argument, NULL, 'C'},
            {"title-format", required_argument, NULL, 't'},
            {"format",       required_argument, NULL, 'o'},
            {"json",         no_argument,       NULL, 'j'},
            {0, 0, 0,                                 0}
    };

    int option;
    int option_index;
    char *name;
    enum blobsync sync = BLOB_SYNC_AUTO;
    bool clip = false;
    bool json = false;

    _cleanup_free_ char *title_format = NULL;
    _cleanup_free_ char *field_format = NULL;

    while ((option = getopt_long(argc, argv, "cCtoj", long_options, &option_index)) != -1) {
        switch (option) {
            case 'c':
                clip = true;
                break;
            case 'C':
                terminal_set_color_mode(parse_color_mode_string(optarg));
                break;
            case 'j':
                json = true;
                break;
            case 'o':
                field_format = xstrdup(optarg);
                break;
            case 't':
                title_format = xstrdup(optarg);
                break;
            case '?':
            default:
                die_usage(cmd_history_usage);
        }
    }

    if (argc - optind < 1)
        die_usage(cmd_history_usage);

    name = argv[optind];

    if (!title_format) {
        title_format = xstrdup(
                TERMINAL_FG_CYAN "%/as" TERMINAL_RESET
                TERMINAL_FG_BLUE "%/ag"
                TERMINAL_BOLD "%an" TERMINAL_RESET
                TERMINAL_FG_GREEN " [id: %ai]" TERMINAL_RESET);
    }
    if (!field_format) {
        field_format = xstrdup(
                TERMINAL_FG_YELLOW "%fn" TERMINAL_RESET ": %fv");
    }

    init_all(sync, key, &session, &blob);

    struct account *found_account = find_unique_account(blob, name);

    if (!found_account)
        die("Could not find specified account(s).");

    char *result = lastpass_get_password_history_json(session, found_account, key);

    if (clip)
        clipboard_open();

    if (json) {
        puts(result);
        goto done;
    }

    print_header(title_format, found_account);

    json_t const *parent = json_create(result, pool, JSON_POOL_SIZE);
    if (parent == NULL) die("Malformed JSON");

    json_t const *history_field = json_getProperty(parent, "history");
    if (history_field == NULL || TINY_JSON_ARRAY != json_getType(history_field)) die("No history present");

    json_t const *entry;
    for (entry = json_getChild(history_field); entry != 0; entry = json_getSibling(entry)) {
        if (JSON_OBJ == json_getType(entry)) {
            char const *date = json_getPropertyValue(entry, "date");
            char const *password = json_getPropertyValue(entry, "value");
            char const *whom = json_getPropertyValue(entry, "value");
            char *decyphered = cipher_aes_decrypt_base64(password, key);

            char *date_copy = calloc(strlen(date) + 1, 1);
            strcpy(date_copy, date);

            char *whom_copy = calloc(strlen(whom) + 1, 1);
            strcpy(whom_copy, whom);

            print_field(field_format, found_account, date_copy, decyphered);
        }
    }

    done:
    session_free(session);
    blob_free(blob);
    free(result);
    return 0;
}
