/*
 * Copyright (c) 2014 LastPass.
 *
 *
 */

#include "xml.h"
#include "util.h"
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

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
