#ifndef JSON_FORMAT_H
#define JSON_FORMAT_H

enum json_field_type {
	BOOL_FIELD,
	STRING_FIELD,
	OBJECT_FIELD
};

struct json_field
{
	const char *name;
	enum json_field_type type;

	/* list of properties */
	struct list_head children;
	struct list_head siblings;

	union {
		bool bool_value;
		const char *string_value;
	} u;
};

void json_format(struct json_field *field, int indent, bool is_last);
void print_json_quoted_string(const char *str);

#endif /* JSON_FORMAT_H */
