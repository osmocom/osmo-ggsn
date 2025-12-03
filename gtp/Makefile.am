# This is _NOT_ the library release version, it's an API version.
# Please read chapter "Library interface versions" of the libtool documentation
# before making any modifications: https://www.gnu.org/software/libtool/manual/html_node/Versioning.html
# If major=current-age is increased, remember to update the dh_strip line in debian/rules!
LIBVERSION=12:0:1

lib_LTLIBRARIES = libgtp.la

AM_CFLAGS = \
	    -fno-builtin \
	    -Wall \
	    -DSBINDIR='"$(sbindir)"' \
	    -I$(top_srcdir)/include \
	    $(LIBOSMOCORE_CFLAGS) \
	    $(LIBOSMOGSM_CFLAGS) \
	    $(NULL)

libgtp_la_SOURCES = \
		    gsn.c \
		    gsn_internal.h \
		    gtp.c \
		    gtp_internal.h \
		    gtp_sgsn_ctx.c \
		    gtp_sgsn_ctx.h \
		    gtpie.c \
		    lookupa.c \
		    lookupa.h \
		    pdp.c \
		    queue.c \
		    queue.h \
		    $(NULL)

libgtp_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined
libgtp_la_LIBADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
