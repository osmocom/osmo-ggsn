bin_PROGRAMS = ggsn

CFLAGS = -O2 -fno-builtin -Wall -ansi -DSBINDIR='"$(sbindir)"' -lgtp

ggsn_SOURCES = ggsn.c tun.c tun.h cmdline.c cmdline.h

cmdline.c: cmdline.ggo
	gengetopt < cmdline.ggo --unamed-opts



