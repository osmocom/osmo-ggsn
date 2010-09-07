bin_PROGRAMS = ggsn

AUTOMAKE_OPTIONS = subdir-objects

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb

ggsn_LDADD = @LIBOBJS@ @EXEC_LDADD@ -lgtp -L../gtp

#ggsn_DEPENDENCIES = ../gtp/libgtp.la

ggsn_SOURCES = ggsn.c ../lib/tun.c ../lib/tun.h cmdline.c cmdline.h ../lib/ippool.h ../lib/ippool.c ../lib/syserr.h ../lib/syserr.c ../lib/lookup.c ../lib/lookup.h
#ggsn_SOURCES = ggsn.c cmdline.c cmdline.h

