/*
 * json parsing routines
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <yajl/yajl_tree.h>
#include "list.h"
#include "blob.h"
#include "util.h"

static char *get_yajl_string(yajl_val parent, const char *field)
{
	const char *path[2] = { 0 };
	path[0] = field;
	yajl_val v = yajl_tree_get(parent, path, yajl_t_string);
	if (!v)
		return NULL;

	return xstrdup(YAJL_GET_STRING(v));
}

static bool get_yajl_bool_string(yajl_val parent, const char *field)
{
	bool result = false;
	char *strval = get_yajl_string(parent, field);
	if (strval && !strcmp(strval, "1"))
		result = true;

	free(strval);
	return result;
}

void json_parse_share_user(yajl_val node, struct share_user *user)
{
	user->uid = get_yajl_string(node, "uid");
	user->username = get_yajl_string(node, "username");
	user->realname = get_yajl_string(node, "name");
	user->read_only = get_yajl_bool_string(node, "readonly");
	user->hide_passwords = !get_yajl_bool_string(node, "give");
	user->admin = get_yajl_bool_string(node, "can_administer");
	user->outside_enterprise = get_yajl_bool_string(node, "external");
	user->accepted = get_yajl_bool_string(node, "accepted");
}

int json_parse_share_getinfo(const char *buf, struct list_head *users)
{
	int ret;
	yajl_val node;
	char errbuf[80] = {0};

	node = yajl_tree_parse(buf, errbuf, sizeof(errbuf));
	if (!node)
		return -EINVAL;

	const char *path[] = { "users", NULL };
	yajl_val v = yajl_tree_get(node, path, yajl_t_array);
	if (!v) {
		ret = -EINVAL;
		goto out;
	}

	for (size_t i = 0; i < YAJL_GET_ARRAY(v)->len; i++) {
		yajl_val child = YAJL_GET_ARRAY(v)->values[i];
		struct share_user *new_user = xcalloc(1, sizeof(*new_user));
		json_parse_share_user(child, new_user);
		list_add_tail(&new_user->list, users);
	}

	path[0] = "groups";
	v = yajl_tree_get(node, path, yajl_t_array);
	if (!v) {
		ret = -EINVAL;
		goto out;
	}

	for (size_t i = 0; i < YAJL_GET_ARRAY(v)->len; i++) {
		yajl_val child = YAJL_GET_ARRAY(v)->values[i];
		struct share_user *new_user = xcalloc(1, sizeof(*new_user));
		json_parse_share_user(child, new_user);

		/*
		 * in groups, "name" goes in username field, but the
		 * username is empty.
		 */
		new_user->is_group = true;
		free(new_user->username);
		new_user->username = new_user->realname;
		new_user->realname = NULL;

		list_add_tail(&new_user->list, users);
	}

	yajl_tree_free(node);
	ret = 0;
out:
	return ret;
}
