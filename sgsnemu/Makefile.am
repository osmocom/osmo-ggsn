bin_PROGRAMS = sgsnemu

AUTOMAKE_OPTIONS = subdir-objects

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb

sgsnemu_LDADD = @LIBOBJS@ @EXEC_LDADD@ -lgtp -L../gtp 

#sgsnemu_DEPENDENCIES = ../gtp/libgtp.la

sgsnemu_SOURCES = sgsnemu.c ../lib/tun.c ../lib/tun.h cmdline.c cmdline.h ../lib/ippool.h ../lib/ippool.c ../lib/syserr.h ../lib/syserr.c ../lib/lookup.c ../lib/lookup.h
#sgsnemu_SOURCES = sgsnemu.c cmdline.c cmdline.h
