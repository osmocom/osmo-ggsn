bin_PROGRAMS = ggsn

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS) $(LIBOSMOCTRL_CFLAGS) $(LIBOSMOVTY_CFLAGS)

ggsn_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS) $(LIBOSMOCTRL_LIBS) $(LIBOSMOVTY_LIBS)

if ENABLE_GTP_KERNEL
AM_CFLAGS += -DGTP_KERNEL
ggsn_LDADD += -lgtpnl
endif

ggsn_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
ggsn_SOURCES = ggsn_vty.c ggsn.c ggsn.h gtp-kernel.h icmpv6.c icmpv6.h checksum.c checksum.h

if ENABLE_GTP_KERNEL
ggsn_SOURCES += gtp-kernel.c
endif
