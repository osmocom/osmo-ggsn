bin_PROGRAMS = osmo-ggsn

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS) $(LIBOSMOCTRL_CFLAGS) $(LIBOSMOVTY_CFLAGS)

osmo_ggsn_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS) $(LIBOSMOCTRL_LIBS) $(LIBOSMOVTY_LIBS)

if ENABLE_GTP_KERNEL
AM_CFLAGS += -DGTP_KERNEL $(LIBGTPNL_CFLAGS)
osmo_ggsn_LDADD += $(LIBGTPNL_LIBS)
endif

osmo_ggsn_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
osmo_ggsn_SOURCES = ggsn_vty.c ggsn.c ggsn.h icmpv6.c icmpv6.h checksum.c checksum.h pco.c pco.h
