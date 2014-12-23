noinst_LIBRARIES = libmisc.a

noinst_HEADERS = gnugetopt.h ippool.h lookup.h syserr.h tun.h

AM_CFLAGS = -O2 -fno-builtin -Wall -DSBINDIR='"$(sbindir)"' -ggdb $(LIBOSMOCORE_CFLAGS)

libmisc_a_SOURCES = getopt1.c getopt.c ippool.c lookup.c tun.c debug.c
