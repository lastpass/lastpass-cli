#ifndef PASSWORD_H
#define PASSWORD_H

char *password_prompt(const char *prompt, const char *error, const char *descfmt, ...);
char *pinentry_unescape(const char *str);
char *pinentry_escape(const char *str);

#endif
