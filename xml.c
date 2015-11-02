/*
 * xml parsing routines
 *
 * Copyright (C) 2014-2015 LastPass.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "blob.h"
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <errno.h>

struct session *xml_ok_session(const char *buf, unsigned const char key[KDF_HASH_LEN])
{
	struct session *session = NULL;
	xmlDoc *doc = NULL;
	xmlNode *root;
	doc = xmlParseMemory(buf, strlen(buf));

	if (!doc)
		goto out;

	root = xmlDocGetRootElement(doc);
	if (root && !xmlStrcmp(root->name, BAD_CAST "response")) {
		for (root = root->children; root; root = root->next) {
			if (!xmlStrcmp(root->name, BAD_CAST "ok"))
				break;
		}
	}
	if (root && !xmlStrcmp(root->name, BAD_CAST "ok")) {
		session = session_new();
		for (xmlAttrPtr attr = root->properties; attr; attr = attr->next) {
			if (!xmlStrcmp(attr->name, BAD_CAST "uid"))
				session->uid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			if (!xmlStrcmp(attr->name, BAD_CAST "sessionid"))
				session->sessionid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			if (!xmlStrcmp(attr->name, BAD_CAST "token"))
				session->token = (char *)xmlNodeListGetString(doc, attr->children, 1);
			if (!xmlStrcmp(attr->name, BAD_CAST "privatekeyenc")) {
				_cleanup_free_ char *private_key = (char *)xmlNodeListGetString(doc, attr->children, 1);
				session_set_private_key(session, key, private_key);
			}
		}
	}
out:
	if (doc)
		xmlFreeDoc(doc);
	if (!session_is_valid(session)) {
		session_free(session);
		return NULL;
	}
	return session;
}

unsigned long long xml_login_check(const char *buf, struct session *session)
{
	_cleanup_free_ char *versionstr = NULL;
	unsigned long long version = 0;
	xmlDoc *doc = NULL;
	xmlNode *root, *child = NULL;

	doc = xmlParseMemory(buf, strlen(buf));

	if (!doc)
		goto out;

	root = xmlDocGetRootElement(doc);
	if (root && !xmlStrcmp(root->name, BAD_CAST "response")) {
		for (child = root->children; child; child = child->next) {
			if (!xmlStrcmp(child->name, BAD_CAST "ok"))
				break;
		}
	}
	if (child) {
		for (xmlAttrPtr attr = child->properties; attr; attr = attr->next) {
			if (!xmlStrcmp(attr->name, BAD_CAST "uid")) {
				free(session->uid);
				session->uid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			} else if (!xmlStrcmp(attr->name, BAD_CAST "sessionid")) {
				free(session->sessionid);
				session->sessionid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			} else if (!xmlStrcmp(attr->name, BAD_CAST "token")) {
				free(session->token);
				session->token = (char *)xmlNodeListGetString(doc, attr->children, 1);
			} else if (!xmlStrcmp(attr->name, BAD_CAST "accts_version")) {
				versionstr = (char *)xmlNodeListGetString(doc, attr->children, 1);
				version = strtoull(versionstr, NULL, 10);
			}
		}
	}
out:
	if (doc)
		xmlFreeDoc(doc);
	return version;
}

char *xml_error_cause(const char *buf, const char *what)
{
	char *result = NULL;
	xmlDoc *doc = NULL;
	xmlNode *root;

	doc = xmlParseMemory(buf, strlen(buf));

	if (!doc)
		goto out;

	root = xmlDocGetRootElement(doc);
	if (root && !xmlStrcmp(root->name, BAD_CAST "response")) {
		for (xmlNode *child = root->children; child; child = child->next) {
			if (!xmlStrcmp(child->name, BAD_CAST "error")) {
				for (xmlAttrPtr attr = child->properties; attr; attr = attr->next) {
					if (!xmlStrcmp(attr->name, BAD_CAST what)) {
						result = (char *)xmlNodeListGetString(doc, attr->children, 1);
						goto out;
					}
				}
				break;
			}
		}
	}
out:
	if (doc)
		xmlFreeDoc(doc);
	if (!result)
		result = xstrdup("unknown");

	return result;
}

/*
 * Check if node has the tag "name", and interpret as a string
 * if so.
 *
 * Return true and update the string pointed to by ptr if the node
 * matches name.
 */
static bool
xml_parse_str(xmlDoc *doc, xmlNode *parent, const char *name, char **ptr)
{
	if (xmlStrcmp(parent->name, BAD_CAST name))
		return false;

	*ptr = (char *) xmlNodeListGetString(doc, parent->xmlChildrenNode, 1);
	return true;
}

/*
 * Check if node has the tag "name", and interpret as an int if so.
 *
 * Return true and update the int pointed to by ptr if the node
 * matches name.
 */
static bool
xml_parse_int(xmlDoc *doc, xmlNode *parent, const char *name, int *ptr)
{
	if (xmlStrcmp(parent->name, BAD_CAST name))
		return false;

	_cleanup_free_ char *str = (char *)
		xmlNodeListGetString(doc, parent->xmlChildrenNode, 1);

	*ptr = atoi(str);
	return true;
}

/*
 * Check if node is for the boolean "name", and interpret as a boolean
 * if so.
 *
 * Return true and update the boolean pointed to by ptr if the node
 * matches name.
 */
static bool
xml_parse_bool(xmlDoc *doc, xmlNode *parent, const char *name, bool *ptr)
{
	int intval;

	if (!xml_parse_int(doc, parent, name, &intval))
		return false;

	*ptr = intval;
	return true;
}

static void
xml_parse_share_permissions(xmlDoc *doc, xmlNode *item, struct share_user *user)
{
	bool tmp;

	for (xmlNode *child = item->children; child; child = child->next) {
		if (xml_parse_bool(doc, child, "canadminister", &user->admin))
			continue;
		if (xml_parse_bool(doc, child, "readonly", &user->read_only))
			continue;
		if (xml_parse_bool(doc, child, "give", &tmp)) {
			user->hide_passwords = !tmp;
			continue;
		}
	}
}

static void
xml_parse_share_user(xmlDoc *doc, xmlNode *item, struct share_user *user)
{
	char *tmp;

	/* process a user item */
	for (xmlNode *child = item->children; child; child = child->next) {
		if (xml_parse_str(doc, child, "realname", &user->realname))
			continue;
		if (xml_parse_str(doc, child, "username", &user->username))
			continue;
		if (xml_parse_str(doc, child, "uid", &user->uid))
			continue;
		if (xml_parse_bool(doc, child, "group", &user->is_group))
			continue;
		if (xml_parse_bool(doc, child, "outsideenterpise", &user->outside_enterprise))
			continue;
		if (xml_parse_bool(doc, child, "accepted", &user->accepted))
			continue;
		if (xml_parse_str(doc, child, "sharingkey", &tmp)) {
			int ret = hex_to_bytes(tmp, &user->sharing_key.key);
			if (ret == 0)
				user->sharing_key.len = strlen(tmp) / 2;
			free(tmp);
			continue;
		}
		if (!xmlStrcmp(child->name, BAD_CAST "permissions"))
			xml_parse_share_permissions(doc, child, user);
	}
}

int xml_parse_share_getinfo(const char *buf, struct list_head *users)
{
	int ret;
	xmlDoc *doc = xmlParseMemory(buf, strlen(buf));

	if (!doc)
		return -EINVAL;

	/*
	 * XML fields are as follows:
	 * xmlresponse
	 *   users
	 *     item
	 *       realname
	 *       uid
	 *       group
	 *       username
	 *       permissions
	 *         readonly
	 *         canadminister
	 *         give
	 *       outsideenterprise
	 *       accepted
	 *     item...
	 */
	xmlNode *root = xmlDocGetRootElement(doc);
	if (!root ||
	    xmlStrcmp(root->name, BAD_CAST "xmlresponse") ||
	    !root->children ||
	    xmlStrcmp(root->children->name, BAD_CAST "users")) {
		ret = -EINVAL;
		goto free_doc;
	}

	xmlNode *usernode = root->children;
	for (xmlNode *item = usernode->children; item; item = item->next) {
		if (xmlStrcmp(item->name, BAD_CAST "item"))
			continue;

		struct share_user *new_user = xcalloc(1, sizeof(*new_user));
		xml_parse_share_user(doc, item, new_user);
		list_add_tail(&new_user->list, users);
	}
	ret = 0;
free_doc:
	xmlFreeDoc(doc);
	return ret;
}

int xml_parse_share_getpubkey(const char *buf, struct share_user *user)
{
	int ret;
	xmlDoc *doc = xmlParseMemory(buf, strlen(buf));
	char *tmp;

	if (!doc)
		return -EINVAL;

	/*
	 * XML fields are as follows:
	 * xmlresponse
	 *   success
	 *   pubkey0
	 *   uid0
	 *   username0
	 */
	xmlNode *root = xmlDocGetRootElement(doc);
	if (!root || xmlStrcmp(root->name, BAD_CAST "xmlresponse") ||
	    !root->children) {
		ret = -EINVAL;
		goto free_doc;
	}

	user->sharing_key.key = NULL;
	user->sharing_key.len = 0;

	for (xmlNode *item = root->children; item; item = item->next) {

		if (xml_parse_str(doc, item, "pubkey0", &tmp)) {
			int ret = hex_to_bytes(tmp, &user->sharing_key.key);
			if (ret == 0)
				user->sharing_key.len = strlen(tmp) / 2;
			free(tmp);
			continue;
		}
		if (xml_parse_str(doc, item, "username0", &user->username))
			continue;
		if (xml_parse_str(doc, item, "uid0", &user->uid))
			continue;
	}
	if (!user->sharing_key.len)
		ret = -ENOENT;
	else
		ret = 0;
free_doc:
	xmlFreeDoc(doc);
	return ret;
}
