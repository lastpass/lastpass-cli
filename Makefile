PREFIX ?= /usr
BUILDDIR=build
CMAKEMAKE=$(BUILDDIR)/Makefile

all: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) all

clean: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) clean

doc-man: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) doc-man

doc-html: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) doc-html

install-doc: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) install-doc

install: $(CMAKEMAKE)
	$(MAKE) -C $(BUILDDIR) install

$(CMAKEMAKE):
	mkdir -p $(BUILDDIR) && cd $(BUILDDIR) && cmake -DCMAKE_INSTALL_PREFIX:PATH=$(PREFIX) ..

.PHONY: all doc-man clean
