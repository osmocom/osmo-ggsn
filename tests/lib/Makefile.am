AM_CFLAGS = \
	    -Wall \
	    -I$(top_srcdir)/include \
	    $(LIBOSMOCORE_CFLAGS) \
	    $(NULL)
AM_LDFLAGS = -no-install

EXTRA_DIST = ippool_test.ok \
	     ippool_test.err \
	     ippool_v6_test.ok \
	     ippool_v6_test.err \
	     $(NULL)

check_PROGRAMS = ippool_test

ippool_test_SOURCES = \
	ippool_test.c \
	$(NULL)

ippool_test_LDADD = \
	$(top_builddir)/lib/libmisc.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)
