/*
 * json formatting routines
 *
 * Copyright (C) 2018 LastPass.
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
#include "blob.h"
#include "util.h"
#include "list.h"
#include "json-format.h"

#define INDENT_SPACES 2

static void json_format(struct json_field *field, int level, bool is_last);

static void print_json_quoted_string(const char *str)
{
	const char *ptr = NULL;

	putchar ('"');
	for (ptr = str; *ptr; ptr++) {
		/* escape some characters according to http://www.ietf.org/rfc/rfc4627.txt */
		switch (*ptr) {
		case '\b': putchar('\\'); putchar('b'); break;
		case '\f': putchar('\\'); putchar('f'); break;
		case '\n': putchar('\\'); putchar('n'); break;
		case '\r': putchar('\\'); putchar('r'); break;
		case '\t': putchar('\\'); putchar('t'); break;
		case '\\': putchar('\\'); putchar('\\'); break;
		case  '"': putchar('\\'); putchar('"'); break;
		default:
			if ((*ptr) < ' ') {
				printf("\\u%04x", *ptr);
			} else {
				putchar(*ptr);
			}
			break;
		}
	}
	putchar ('"');
}

static void indent(int level)
{
	for (int i = 0; i < level * INDENT_SPACES; i++)
		putchar(' ');
}

static
void json_format_string(struct json_field *field, int level, bool is_last)
{
	indent(level);
	if (field->name) {
		print_json_quoted_string(field->name);
		printf(": ");
	}
	print_json_quoted_string(field->u.string_value);
	printf("%c\n", is_last ? ' ' : ',');
}

static
void json_format_array(struct json_field *field, int level, bool is_last)
{
	struct json_field *child;
	struct json_field *last;

	if (field->type != JSON_ARRAY)
		return;

	last = list_last_entry_or_null(&field->children, struct json_field,
				       siblings);
	indent(level);

	if (field->name) {
		print_json_quoted_string(field->name);
		printf(": ");
	}
	printf ("[\n");
	list_for_each_entry(child, &field->children, siblings) {
		json_format(child, level + 1, child == last);
	}
	indent(level);
	printf ("]%c\n", is_last ? ' ' : ',');
}

static
void json_format_object(struct json_field *field, int level, bool is_last)
{
	struct json_field *child;
	struct json_field *last;

	if (field->type != JSON_OBJECT)
		return;

	last = list_last_entry_or_null(&field->children, struct json_field,
				       siblings);
	indent(level);

	if (field->name) {
		print_json_quoted_string(field->name);
		printf(": ");
	}
	printf ("{\n");
	list_for_each_entry(child, &field->children, siblings) {
		json_format(child, level + 1, child == last);
	}
	indent(level);
	printf ("}%c\n", is_last ? ' ' : ',');
}

static
void json_format(struct json_field *field, int level, bool is_last)
{
	switch (field->type) {
	case JSON_OBJECT:
		json_format_object(field, level, is_last);
		break;
	case JSON_STRING:
		json_format_string(field, level, is_last);
		break;
	case JSON_ARRAY:
		json_format_array(field, level, is_last);
		break;
	default:
		printf("unhandled type: %d\n", field->type);
	}
}

static
void json_add_string_field(struct json_field *object,
			   const char *name, const char *value)
{
	if (!value)
		return;

	struct json_field *field = xmalloc(sizeof(struct json_field));
	field->name = name;
	field->type = JSON_STRING;
	field->u.string_value = value;

	list_add_tail(&field->siblings, &object->children);
}

static
void account_to_json_field(struct account *account, struct json_field *obj)
{
	obj->name = NULL;
	obj->type = JSON_OBJECT;

	json_add_string_field(obj, "id", account->id);

	json_add_string_field(obj, "name", account->name);
	json_add_string_field(obj, "fullname", account->fullname);
	json_add_string_field(obj, "username", account->username);
	json_add_string_field(obj, "password", account->password);
	json_add_string_field(obj, "last_modified_gmt", account->last_modified_gmt);
	json_add_string_field(obj, "last_touch", account->last_touch);
	if (account->share)
		json_add_string_field(obj, "share", account->share->name);
	json_add_string_field(obj, "group", account->group);
	json_add_string_field(obj, "url", account->url);
	json_add_string_field(obj, "note", account->note);
}

static void json_free_account_fields(struct json_field *obj)
{
	struct json_field *field, *tmp;

	list_for_each_entry_safe(field, tmp, &obj->children, siblings) {
		free(field);
	}
}

void json_format_account_list(struct list_head *accounts)
{
	struct account *account;
	struct json_field *child, *tmp;
	struct json_field array = {
		.type = JSON_ARRAY
	};
	INIT_LIST_HEAD(&array.children);

	list_for_each_entry(account, accounts, match_list) {
		struct json_field *object = xmalloc(sizeof(*object));
		object->name = NULL;
		object->type = JSON_OBJECT;
		INIT_LIST_HEAD(&object->children);

		account_to_json_field(account, object);
		list_add_tail(&object->siblings, &array.children);
	}
	json_format(&array, 0, true);

	list_for_each_entry_safe(child, tmp, &array.children, siblings) {
		json_free_account_fields(child);
		free(child);
	}
}
