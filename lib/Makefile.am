noinst_LIBRARIES = libmisc.a

noinst_HEADERS = gnugetopt.h ippool.h lookup.h syserr.h tun.h in46_addr.h netdev.h gtp-kernel.h netns.h util.h icmpv6.h checksum.h

AM_CFLAGS = \
	    -fno-builtin \
	    -Wall \
	    -DSBINDIR='"$(sbindir)"' \
	    $(LIBOSMOCORE_CFLAGS) \
	    $(NULL)

libmisc_a_SOURCES = getopt1.c getopt.c ippool.c lookup.c tun.c debug.c in46_addr.c netdev.c netns.c util.c icmpv6.c checksum.c

if ENABLE_GTP_KERNEL
AM_CFLAGS += -DGTP_KERNEL $(LIBGTPNL_CFLAGS)
libmisc_a_SOURCES += gtp-kernel.c
endif
