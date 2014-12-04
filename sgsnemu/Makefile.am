bin_PROGRAMS = sgsnemu

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS)

sgsnemu_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS)
sgsnemu_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
sgsnemu_SOURCES = sgsnemu.c cmdline.c cmdline.h
