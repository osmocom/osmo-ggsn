# XSL stylesheets downloaded from http://docbook.sourceforge.net/release/xsl/current/html/
# Makefile from BitBake/OpenEmbedded manuals

EXTRA_DEPS = gen-ggsn-vty-docbook

topdir = .
ggsn_reference = $(topdir)/osmoggsn-vty-reference.xml
manuals = $(ggsn_reference)
# types = pdf txt rtf ps xhtml html man tex texi dvi
# types = pdf txt
types = $(docbooktotypes)
docbooktotypes = pdf
# htmlcssfile =
# htmlcss =

TOPDIR := ..
ASCIIDOCS := osmoggsn-usermanual

include $(TOPDIR)/build/Makefile.asciidoc.inc
include $(TOPDIR)/build/Makefile.inc

osmoggsn-usermanual.pdf: chapters/*.adoc

clean:
	-rm -rf $(cleanfiles)
	-rm osmoggsn-usermanual__*.svg osmoggsn-usermanual__*.png
	-rm osmoggsn-usermanual.check

gen-ggsn-vty-docbook: FORCE
	$(call command,xsltproc -o generated/combined1.xml \
		--stringparam with $(PWD)/../common/vty_additions.xml \
		$(MERGE_DOC) vty/ggsn_vty_reference.xml, \
		XSLTPROC,Merging Common VTY)
	$(call command,xsltproc -o generated/combined2.xml \
		--stringparam with $(PWD)/vty/ggsn_vty_additions.xml \
		$(MERGE_DOC) generated/combined1.xml, \
		XSLTPROC,Merging GGSN VTY)
	$(call command,xsltproc ../vty_reference.xsl generated/combined2.xml > generated/docbook_vty.xml, \
		XSLTPROC,Converting GGSN VTY to DocBook)
