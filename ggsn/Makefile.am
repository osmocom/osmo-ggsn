bin_PROGRAMS = ggsn

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib

CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -ansi -DSBINDIR='"$(sbindir)"' -lgtp

ggsn_SOURCES = ggsn.c tun.c tun.h cmdline.c cmdline.h




