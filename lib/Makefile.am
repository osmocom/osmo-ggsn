noinst_LIBRARIES = libmisc.a

noinst_HEADERS = \
		 checksum.h \
		 gnugetopt.h \
		 gtp-kernel.h \
		 icmpv6.h \
		 in46_addr.h \
		 ippool.h \
		 lookup.h \
		 netdev.h \
		 netns.h \
		 syserr.h \
		 tun.h \
		 util.h \
		 $(NULL)

AM_CFLAGS = \
	    -fno-builtin \
	    -Wall \
	    -DSBINDIR='"$(sbindir)"' \
	    $(LIBOSMOCORE_CFLAGS) \
	    $(NULL)

libmisc_a_SOURCES = \
		    checksum.c \
		    debug.c \
		    getopt.c \
		    getopt1.c \
		    icmpv6.c \
		    in46_addr.c \
		    ippool.c \
		    lookup.c \
		    netdev.c \
		    netns.c \
		    tun.c \
		    util.c \
		    $(NULL)

if ENABLE_GTP_KERNEL
AM_CFLAGS += -DGTP_KERNEL $(LIBGTPNL_CFLAGS)
libmisc_a_SOURCES += gtp-kernel.c
endif
