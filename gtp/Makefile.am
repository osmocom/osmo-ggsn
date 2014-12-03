lib_LTLIBRARIES = libgtp.la

include_HEADERS = gtp.h pdp.h

AM_CFLAGS = -O2 -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS)

libgtp_la_SOURCES = gtp.c gtp.h gtpie.c gtpie.h pdp.c pdp.h lookupa.c lookupa.h queue.c queue.h
libgtp_la_LIBADD = $(LIBOSMOCORE_LIBS)




