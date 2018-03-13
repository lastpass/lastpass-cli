#ifndef JSON_FORMAT_H
#define JSON_FORMAT_H

enum json_field_type {
	JSON_STRING,
	JSON_ARRAY,
	JSON_OBJECT
};

/*
 * Stores a JSON record to be formatted.
 *
 * Type field dictates which union is used for primitive types.
 * For both objects and arrays, children holds the items that are
 * assigned to the container, and those fields are linked via
 * siblings pointer.  The only difference between an array and an
 * object is that the children will not have names in the case of
 * an array.
 */
struct json_field
{
	const char *name;
	enum json_field_type type;

	/* list of properties */
	struct list_head children;
	struct list_head siblings;

	union {
		const char *string_value;
	} u;
};

void json_format_account_list(struct list_head *accounts);

#endif /* JSON_FORMAT_H */
