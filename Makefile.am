#
#  Makefile.am
#
ACLOCAL_AMFLAGS=-Im4
AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=lastpass
lastpass_CFLAGS=$(LIBXML2_CFLAGS) $(LIBXML2_LIBS)
lasspass_CPPFLAGS=-Wall -Wextra -Wformat -Wformat-security -pedantic -fomit-frame-pointer
lastpass_SOURCES= \
src/certificate.h \
src/version.h \
src/agent.c \
src/agent.h \
src/blob.c \
src/blob.h \
src/cipher.c \
src/cipher.h \
src/clipboard.c \
src/clipboard.h \
src/cmd.c \
src/cmd-duplicate.c \
src/cmd-edit.c \
src/cmd-generate.c \
src/cmd.h \
src/cmd-login.c \
src/cmd-logout.c \
src/cmd-ls.c \
src/cmd-rm.c \
src/cmd-show.c \
src/cmd-sync.c \
src/config.c \
src/config.h \
src/endpoints.c \
src/endpoints.h \
src/endpoints-login.c \
src/http.c \
src/http.h \
src/kdf.c \
src/kdf.h \
src/lpass.c \
src/password.c \
src/password.h \
src/process.c \
src/process.h \
src/session.c \
src/session.h \
src/terminal.c \
src/terminal.h \
src/upload-queue.c \
src/upload-queue.h \
src/util.c \
src/util.h \
src/xml.c \
src/xml.h

#man1_MANS=lastpass.1.txt
EXTRA_DIST=lastpass.1.txt m4
