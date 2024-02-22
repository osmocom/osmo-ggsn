bin_PROGRAMS = osmo-ggsn

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = \
	    -D_GNU_SOURCE \
	    -fno-builtin \
	    -Wall \
	    -DSBINDIR='"$(sbindir)"' \
	    $(LIBOSMOCORE_CFLAGS) \
	    $(LIBOSMOCTRL_CFLAGS) \
	    $(LIBOSMOVTY_CFLAGS) \
	    $(NULL)

osmo_ggsn_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS) $(LIBOSMOCTRL_LIBS) $(LIBOSMOVTY_LIBS)

if ENABLE_GTP_KERNEL
AM_CFLAGS += -DGTP_KERNEL $(LIBGTPNL_CFLAGS)
osmo_ggsn_LDADD += $(LIBGTPNL_LIBS)
endif

osmo_ggsn_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
osmo_ggsn_SOURCES = ggsn_main.c ggsn_vty.c ggsn.c ggsn.h sgsn.c sgsn.h pco.c pco.h
