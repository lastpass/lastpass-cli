#ifndef FIDO2_H
#define FIDO2_H

char *fido2_login_credential(const char *assertion_options, const char *origin,
			     char **error);

#endif
