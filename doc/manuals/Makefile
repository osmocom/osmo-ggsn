# XSL stylesheets downloaded from http://docbook.sourceforge.net/release/xsl/current/html/
# Makefile from BitBake/OpenEmbedded manuals

TOPDIR := ..
ASCIIDOCS := osmoggsn-usermanual

include $(TOPDIR)/build/Makefile.asciidoc.inc
include $(TOPDIR)/build/Makefile.inc

osmoggsn-usermanual.pdf: chapters/*.adoc

clean:
	rm -rf $(cleanfiles)
