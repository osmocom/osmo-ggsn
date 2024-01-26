# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
# If major=current-age is increased, remember to update the dh_strip line in debian/rules!
LIBVERSION=9:1:3

lib_LTLIBRARIES = libgtp.la

include_HEADERS = gtp.h gsn.h pdp.h gtpie.h

AM_CFLAGS = \
	    -fno-builtin \
	    -Wall \
	    -DSBINDIR='"$(sbindir)"' \
	    $(LIBOSMOCORE_CFLAGS) \
		$(LIBOSMOGSM_CFLAGS) \
	    $(NULL)

libgtp_la_SOURCES = \
		    gsn.c \
		    gsn.h \
		    gtp.c \
		    gtp.h \
		    gtpie.c \
		    gtpie.h \
		    lookupa.c \
		    lookupa.h \
		    pdp.c \
		    pdp.h \
		    queue.c \
		    queue.h \
		    $(NULL)

libgtp_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined
libgtp_la_LIBADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
