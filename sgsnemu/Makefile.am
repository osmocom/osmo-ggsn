bin_PROGRAMS = sgsnemu

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb

sgsnemu_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a
sgsnemu_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
sgsnemu_SOURCES = sgsnemu.c cmdline.c cmdline.h
