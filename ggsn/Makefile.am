bin_PROGRAMS = ggsn

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb

ggsn_LDADD = @LIBOBJS@ @EXEC_LDADD@ -lgtp -L../gtp

#ggsn_DEPENDENCIES = ../gtp/libgtp.la

ggsn_SOURCES = ggsn.c tun.c tun.h cmdline.c cmdline.h ippool.h ippool.c syserr.h syserr.c lookup.c lookup.h

