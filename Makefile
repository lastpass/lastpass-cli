PREFIX ?= /usr
MANDIR ?= $(PREFIX)/share/man
BUILDDIR=build
CMAKEMAKE=$(BUILDDIR)/Makefile
CMAKEOPTS=-DCMAKE_INSTALL_PREFIX:PATH=$(PREFIX) -DCMAKE_INSTALL_MANDIR:PATH=$(MANDIR)

all: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) all

clean: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) clean
	$(RM) -r $(BUILDDIR)

doc-man: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) doc-man

doc-html: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) doc-html

install-doc: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) install-doc

install: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) install

test: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) lpass-test && $(MAKE) -C $(BUILDDIR) test

uninstall: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) uninstall

$(CMAKEMAKE):
	mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && cmake $(CMAKEOPTS) ..

.PHONY: all doc-man clean $(CMAKEMAKE)
