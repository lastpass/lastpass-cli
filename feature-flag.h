#ifndef FEATUREFLAG_H
#define FEATUREFLAG_H

#include <libxml/tree.h>
#include <stdbool.h>

struct feature_flag {
	bool url_encryption_enabled;
};

void feature_flag_load_xml_attr(struct feature_flag *feature_flag, xmlDoc *doc, xmlAttrPtr attr);

#endif
