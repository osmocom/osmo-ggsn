bin_PROGRAMS = ggsn

LDFLAGS = -lgtp -L../gtp @EXEC_LDFLAGS@

CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb

ggsn_LDADD = @LIBOBJS@

ggsn_SOURCES = ggsn.c tun.c tun.h cmdline.c cmdline.h ippool.h ippool.c syserr.h syserr.c

