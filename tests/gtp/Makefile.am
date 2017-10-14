AM_CFLAGS = -Wall -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS) -g

EXTRA_DIST = \
	gtpie_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	gtpie_test \
	$(NULL)

gtpie_test_SOURCES = \
	gtpie_test.c \
	$(NULL)

gtpie_test_LDADD = \
	$(top_builddir)/lib/debug.o \
	$(top_builddir)/gtp/libgtp.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)
