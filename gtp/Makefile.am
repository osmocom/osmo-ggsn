# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
LIBVERSION=1:0:0
lib_LTLIBRARIES = libgtp.la

include_HEADERS = gtp.h pdp.h gtpie.h

AM_CFLAGS = -O2 -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS)

libgtp_la_SOURCES = gtp.c gtp.h gtpie.c gtpie.h pdp.c pdp.h lookupa.c lookupa.h queue.c queue.h
libgtp_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined
libgtp_la_LIBADD = $(LIBOSMOCORE_LIBS)




