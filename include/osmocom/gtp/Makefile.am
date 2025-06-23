version.h: version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

EXTRA_DIST = \
	version.h.tpl \
	$(NULL)

libgtp_HEADERS = \
	gsn.h \
	gtp.h \
	gtpie.h \
	pdp.h \
	version.h \
	$(NULL)

libgtpdir = $(includedir)/osmocom/gtp
