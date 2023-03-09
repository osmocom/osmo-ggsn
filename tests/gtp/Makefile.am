AM_CFLAGS = -Wall -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS)

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
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

queue_test_LDADD = \
	$(top_builddir)/lib/debug.o \
	$(top_builddir)/gtp/libgtp.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)
