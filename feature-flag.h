#ifndef FEATUREFLAG_H
#define FEATUREFLAG_H

#include <libxml/tree.h>
#include <stdbool.h>

struct feature_flag {
	char *url_encryption;
};

void feature_flag_load_xml_attr(struct feature_flag *feature_flag, xmlDoc *doc, xmlAttrPtr attr);
void feature_flag_free(struct feature_flag *feature_flag);
bool feature_flag_is_url_encryption_enabled(struct feature_flag *feature_flag);

#endif
