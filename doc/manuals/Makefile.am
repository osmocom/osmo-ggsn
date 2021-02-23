EXTRA_DIST = osmoggsn-usermanual.adoc \
    osmoggsn-usermanual-docinfo.xml \
    osmoggsn-vty-reference.xml \
    regen_doc.sh \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmoggsn-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmoggsn-vty-reference.xml

  BUILT_REFERENCE_XML = $(builddir)/vty/ggsn_vty_reference.xml
  $(builddir)/vty/ggsn_vty_reference.xml: $(top_builddir)/ggsn/osmo-ggsn
	mkdir -p $(builddir)/vty
	$(top_builddir)/ggsn/osmo-ggsn --vty-ref-xml > $@

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY=osmo-ggsn
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
