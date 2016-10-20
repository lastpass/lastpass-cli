#ifndef FORMAT_H
#define FORMAT_H

char *get_display_fullname(struct account *account);
char *format_timestamp(char *timestamp, bool utc);
void format_account(struct buffer *buf, char *format_str,
		    struct account *account);

#endif
