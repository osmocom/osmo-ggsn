bin_PROGRAMS = sgsnemu

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib

CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -ansi -DSBINDIR='"$(sbindir)"' -lgtp -L../gtp

sgsnemu_SOURCES = sgsnemu.c tun.c tun.h cmdline.c cmdline.h




