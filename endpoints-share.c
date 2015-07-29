/*
 * Copyright (c) 2014-2015 LastPass.
 */
#include "endpoints.h"
#include "http.h"
#include "version.h"
#include "xml.h"
#include "config.h"
#include "util.h"
#include "upload-queue.h"
#include <string.h>
#include <errno.h>
#include <curl/curl.h>

int lastpass_share_getinfo(const struct session *session, const char *shareid,
			   struct list_head *users)
{
	_cleanup_free_ char *reply = NULL;
	size_t len;

	reply = http_post_lastpass("share.php", session->sessionid, &len,
				   "sharejs", "1", "getinfo", "1",
				   "id", shareid, "xmlr", "1", NULL);
	if (!reply)
		return -EPERM;

	xml_parse_share_getinfo(reply, users);
	return 0;
}
