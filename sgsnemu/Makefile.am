bin_PROGRAMS = sgsnemu

AM_LDFLAGS = @EXEC_LDFLAGS@

AM_CFLAGS = \
	    -D_GNU_SOURCE \
	    -fno-builtin \
	    -Wall \
	    -DSBINDIR='"$(sbindir)"' \
	    $(LIBOSMOCORE_CFLAGS) \
	    $(NULL)

sgsnemu_LDADD = @EXEC_LDADD@ -lgtp -L../gtp ../lib/libmisc.a $(LIBOSMOCORE_LIBS)

if ENABLE_GTP_KERNEL
AM_CFLAGS += \
	     -DGTP_KERNEL \
	     $(LIBGTPNL_CFLAGS) \
	     $(NULL)
sgsnemu_LDADD += $(LIBGTPNL_LIBS)
endif

sgsnemu_DEPENDENCIES = ../gtp/libgtp.la ../lib/libmisc.a
sgsnemu_SOURCES = sgsnemu.c cmdline.c cmdline.h
