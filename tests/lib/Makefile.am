AM_CFLAGS = -Wall -I$(top_srcdir)/include $(LIBOSMOCORE_CFLAGS) -g

EXTRA_DIST = ippool_test.ok \
	     ippool_test.err \
	     ippool_v6_test.ok \
	     ippool_v6_test.err \
	     in46a_test.ok \
	     in46a_v6_test.ok

check_PROGRAMS = ippool_test in46a_test

ippool_test_SOURCES = \
	ippool_test.c \
	$(NULL)

ippool_test_LDADD = \
	$(top_builddir)/lib/libmisc.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

in46a_test_SOURCES = \
	in46a_test.c \
	$(NULL)

in46a_test_LDADD = \
	$(top_builddir)/lib/libmisc.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)
