bin_PROGRAMS = sgsnemu

LDFLAGS = -Wl,--rpath -Wl,/usr/local/lib @EXEC_LDFLAGS@

CFLAGS = -O2 -D_GNU_SOURCE -fno-builtin -Wall -ansi -DSBINDIR='"$(sbindir)"' -ggdb -lgtp -L../gtp

sgsnemu_SOURCES = sgsnemu.c tun.c tun.h cmdline.c cmdline.h ippool.h ippool.c syserr.h syserr.c




