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
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY=osmo-ggsn
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
