bin_PROGRAMS = sgsnemu

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb

sgsnemu_LDADD = @LIBOBJS@ @EXEC_LDADD@ -lgtp -L../gtp 

#sgsnemu_DEPENDENCIES = ../gtp/libgtp.la

sgsnemu_SOURCES = sgsnemu.c tun.c tun.h cmdline.c cmdline.h ippool.h ippool.c syserr.h syserr.c lookup.c lookup.h
