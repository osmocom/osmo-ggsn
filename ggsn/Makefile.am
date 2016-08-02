bin_PROGRAMS = ggsn

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS) $(LIBOSMOCTRL_CFLAGS)

if ENABLE_GTP_KERNEL
AM_CFLAGS += -DGTP_KERNEL
ggsn_LDADD = @EXEC_LDADD@ -lgtp -lgtpnl -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS) $(LIBOSMOCTRL_LIBS)
else
ggsn_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS) $(LIBOSMOCTRL_LIBS)
endif

ggsn_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
ggsn_SOURCES = ggsn.c cmdline.c cmdline.h gtp-kernel.h

if ENABLE_GTP_KERNEL
ggsn_SOURCES += gtp-kernel.c
endif
