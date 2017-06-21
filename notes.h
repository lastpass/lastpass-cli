#ifndef NOTE_TYPES
#define NOTE_TYPES

#include <stdbool.h>

enum note_type {
	NOTE_TYPE_NONE = -1,
	NOTE_TYPE_AMEX,
	NOTE_TYPE_BANK,
	NOTE_TYPE_CREDIT,
	NOTE_TYPE_DATABASE,
	NOTE_TYPE_DRIVERS_LICENSE,
	NOTE_TYPE_EMAIL,
	NOTE_TYPE_HEALTH_INSURANCE,
	NOTE_TYPE_IM,
	NOTE_TYPE_INSURANCE,
	NOTE_TYPE_MASTERCARD,
	NOTE_TYPE_MEMBERSHIP,
	NOTE_TYPE_PASSPORT,
	NOTE_TYPE_SERVER,
	NOTE_TYPE_SOFTWARE_LICENSE,
	NOTE_TYPE_SSH_KEY,
	NOTE_TYPE_SSN,
	NOTE_TYPE_VISA,
	NOTE_TYPE_WIFI,
	NUM_NOTE_TYPES,		/* keep last */
};

#define MAX_FIELD_CT 12
struct note_template {
	const char *shortname;
	const char *name;
	const char *fields[MAX_FIELD_CT + 1];
};

extern struct note_template note_templates[];

const char *notes_get_name(enum note_type note_type);
bool note_field_is_multiline(enum note_type note_type, const char *field);
bool note_has_field(enum note_type note_type, const char *field);
enum note_type notes_get_type_by_shortname(const char *shortname);
enum note_type notes_get_type_by_name(const char *type_str);
char *note_type_usage();

#endif /* NOTE_TYPES */
