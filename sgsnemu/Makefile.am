bin_PROGRAMS = sgsnemu

CFLAGS = -O2 -fno-builtin -Wall -ansi -DSBINDIR='"$(sbindir)"' -lgtp

sgsnemu_SOURCES = sgsnemu.c tun.c tun.h cmdline.c cmdline.h

cmdline.c: cmdline.ggo
	gengetopt < cmdline.ggo --unamed-opts --conf-parser



