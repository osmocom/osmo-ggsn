bin_PROGRAMS = ggsn

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib @EXEC_LDFLAGS@

CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb -lgtp -L../gtp

ggsn_LDADD = @LIBOBJS@

ggsn_SOURCES = ggsn.c tun.c tun.h cmdline.c cmdline.h ippool.h ippool.c syserr.h syserr.c




