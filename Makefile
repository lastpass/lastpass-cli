PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man

CFLAGS ?= -O3 -march=native -fomit-frame-pointer -pipe
CFLAGS += -std=gnu99 -D_GNU_SOURCE
CFLAGS += -pedantic -Wall -Wextra -Wno-language-extension-token
CFLAGS += -MMD

UNAME_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(UNAME_S),Darwin)
SDKROOT ?= $(shell xcodebuild -version -sdk macosx | sed -n 's/^Path: \(.*\)/\1/p')
CFLAGS += -Wno-deprecated-declarations -isysroot $(SDKROOT) -I$(SDKROOT)/usr/include/libxml2
LDLIBS = -lcurl -lxml2 -lssl -lcrypto
else
CFLAGS += $(shell pkg-config --cflags libxml-2.0 2>/dev/null || echo -I/usr/include/libxml2) -I/usr/local/include
LDLIBS = -lcurl $(shell pkg-config --libs libxml-2.0 2>/dev/null || echo -lxml2) -lssl -lcrypto
ifeq ($(UNAME_S),OpenBSD)
LDLIBS += -lkvm
endif
endif

all: lpass
doc-man: lpass.1
doc-html: lpass.1.html
doc: doc-man doc-html

lpass: $(patsubst %.c,%.o,$(wildcard *.c))
%.1: %.1.txt
	a2x --no-xmllint -f manpage $<
%.1.html: %.1.txt
	asciidoc -b html5 -a data-uri -a icons -a toc2 $<

http.c: certificate.h
certificate.h: thawte.pem
	awk 'BEGIN {printf "#define CERTIFICATE_THAWTE \""} {printf "%s\\n", $$0} END {printf "\"\n"}' thawte.pem > certificate.h || rm -f certificate.h

install-doc: doc-man
	@install -v -d "$(DESTDIR)$(MANDIR)/man1" && install -m 0644 -v lpass.1 "$(DESTDIR)$(MANDIR)/man1/lpass.1"

install: all
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -m 0755 -v lpass "$(DESTDIR)$(BINDIR)/lpass"

uninstall:
	@rm -vrf "$(DESTDIR)$(MANDIR)/man1/lpass.1" "$(DESTDIR)$(BINDIR)/lpass"
	@rmdir "$(DESTDIR)$(MANDIR)/man1" "$(DESTDIR)$(BINDIR)" 2>/dev/null || true

clean:
	rm -f lpass *.o *.d lpass.1 lpass.1.html certificate.h lpass.exe

analyze: clean
	CFLAGS=-g scan-build -enable-checker alpha.core -enable-checker alpha.deadcode -enable-checker alpha.security -enable-checker alpha.unix -enable-checker security -enable-checker core -enable-checker deadcode -enable-checker unix -disable-checker alpha.core.PointerSub --view --keep-going $(MAKE) lpass

.PHONY: all doc doc-man doc-html test-deps clean analyze

-include *.d
