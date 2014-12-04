bin_PROGRAMS = ggsn

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS)

ggsn_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS)
ggsn_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
ggsn_SOURCES = ggsn.c cmdline.c cmdline.h

