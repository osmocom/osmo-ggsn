AM_CFLAGS = -Wall -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = -no-install

EXTRA_DIST = \
	gtpie_test.ok \
	queue_test.ok \
	$(NULL)

check_PROGRAMS = \
	gtpie_test \
	queue_test \
	$(NULL)

gtpie_test_SOURCES = \
	gtpie_test.c \
	$(NULL)

queue_test_SOURCES = \
	queue_test.c \
	$(NULL)

gtpie_test_LDADD = \
	$(top_builddir)/lib/debug.o \
	$(top_builddir)/gtp/libgtp.la \
	$(top_builddir)/lib/libmisc.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

queue_test_LDADD = \
	$(top_builddir)/lib/debug.o \
	$(top_builddir)/gtp/libgtp.la \
	$(top_builddir)/lib/libmisc.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)
