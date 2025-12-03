# Process this file with autoconf to produce a configure script.
AC_INIT([osmo-ggsn],[m4_esyscmd(./git-version-gen .tarball-version)],[osmocom-net-gprs@lists.osmocom.org])
AC_CONFIG_SRCDIR([gtp/gtp.c])
AC_CONFIG_HEADERS([config.h])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AC_CONFIG_TESTDIR(tests)
AC_CANONICAL_HOST

CFLAGS="$CFLAGS -std=gnu11"

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
LT_INIT

dnl patching ${archive_cmds} to affect generation of file "libtool" to fix linking with clang
AS_CASE(["$LD"],[*clang*],
  [AS_CASE(["${host_os}"],
     [*linux*],[archive_cmds='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'])])

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_LIBOBJ_DIR([lib])

AC_ARG_ENABLE(static-exec,
 [  --enable-static-exec  Enable static linking of executables],
 [ EXEC_LDFLAGS="-all-static"])

AC_SUBST(EXEC_LDFLAGS)


case "${host}" in
  i*86-*-linux-gnu*)
    EXEC_LDADD="" ;;
  *solaris*)
    EXEC_LDADD="-lresolv -lsocket -lnsl" ;;
esac

AC_SUBST(EXEC_LDADD)


# Checks for libraries.
# FIXME: Replace `main' with a function in `-le':
#AC_CHECK_LIB([e], [main])
# FIXME: Replace `main' with a function in `-lgtp':
#AC_CHECK_LIB([gtp], [main])
# FIXME: Replace `main' with a function in `-links':
#AC_CHECK_LIB([inks], [main])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl GTP Linux kernel dependencies
AC_ARG_ENABLE([gtp-linux],
	AS_HELP_STRING([--enable-gtp-linux], [Build GTP tunneling Linux kernel]),
	[enable_gtp_linux="$enableval"], [enable_gtp_linux="no"])

AS_IF([test "x$enable_gtp_linux" = "xyes"], [
	PKG_CHECK_MODULES([LIBGTPNL], [libgtpnl >= 1.3.0])
])

AM_CONDITIONAL([ENABLE_GTP_KERNEL], [test "$enable_gtp_linux" = "yes"])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Check for if header. Some versions of linux/if.h fail without sys/socket.h included beforehand:
# see https://algorithmicallyrandom.blogspot.com/2012/07/error-on-including-include.html
AC_CHECK_HEADERS([linux/if.h net/if.h], [], [], [#ifdef HAVE_SYS_SOCKET_H
                                                # include <sys/socket.h>
                                                # endif
                                                ])

# Check for tun header
AC_CHECK_HEADERS([linux/if_tun.h net/if_tun.h])

# Check for netlink and rtnetlink headers
AC_CHECK_HEADERS([linux/netlink.h linux/rtnetlink.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# check for ifaliasreq
AC_MSG_CHECKING(whether struct ifaliasreq exist)
AH_TEMPLATE(HAVE_IFALIASREQ)
AC_EGREP_HEADER(ifaliasreq, net/if.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE([HAVE_IFALIASREQ])],
 AC_MSG_RESULT(no))

# check for ifreq.ifru_netmask
AC_MSG_CHECKING(whether struct ifreq.ifru_netmask exist)
AH_TEMPLATE(HAVE_IFREQ_IFRU_NETMASK)
AC_EGREP_HEADER(ifru_netmask, linux/if.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE([HAVE_IFREQ_IFRU_NETMASK])],
 AC_MSG_RESULT(no))


# check for rt_msghdr
AC_MSG_CHECKING(whether struct rt_msghdr exist)
AH_TEMPLATE(HAVE_RT_MSGHDR)
AC_EGREP_HEADER(rt_msghdr, net/route.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE([HAVE_RT_MSGHDR])],
 AC_MSG_RESULT(no))

AC_MSG_CHECKING(whether struct iphdr exists)
AH_TEMPLATE(HAVE_IPHDR)
AC_EGREP_HEADER(struct iphdr, netinet/ip.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE([HAVE_IPHDR])],
 AC_MSG_RESULT(no))

# Address generation modes (enum) implemented in linux 3.17 (bc91b0f07ada5535427373a4e2050877bcc12218)
# /proc/sys/net/ipv6/conf/${iface}/addr_gen_mode was added in linux 4.11 (d35a00b8e33dab7385f724e713ae71c8be0a49f4)
AC_MSG_CHECKING(whether enum in6_addr_gen_mode.IN6_ADDR_GEN_MODE_NONE exists)
AH_TEMPLATE(HAVE_IN6_ADDR_GEN_MODE_NONE)
AC_EGREP_HEADER(IN6_ADDR_GEN_MODE_NONE, linux/if_link.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE([HAVE_IN6_ADDR_GEN_MODE_NONE])],
 AC_MSG_RESULT(no))

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
# AC_FUNC_MALLOC
# AC_FUNC_MEMCMP
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset select socket strdup strerror strtol])
AC_CHECK_FUNCS(inet_aton inet_addr, break)

# check for getopt in standard library
adl_FUNC_GETOPT_LONG

AM_INIT_AUTOMAKE([foreign])

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 1.12.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 1.12.0)
PKG_CHECK_MODULES(LIBOSMOCTRL, libosmoctrl >= 1.12.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 1.12.0)

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

# Generate manuals
AC_ARG_ENABLE(manuals,
	[AS_HELP_STRING(
		[--enable-manuals],
		[Generate manual PDFs [default=no]],
	)],
	[osmo_ac_build_manuals=$enableval], [osmo_ac_build_manuals="no"])
AM_CONDITIONAL([BUILD_MANUALS], [test x"$osmo_ac_build_manuals" = x"yes"])
AC_ARG_VAR(OSMO_GSM_MANUALS_DIR, [path to common osmo-gsm-manuals files, overriding pkg-config and "../osmo-gsm-manuals"
	fallback])
if test x"$osmo_ac_build_manuals" = x"yes"
then
	# Find OSMO_GSM_MANUALS_DIR (env, pkg-conf, fallback)
	if test -n "$OSMO_GSM_MANUALS_DIR"; then
		echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from env)"
	else
		OSMO_GSM_MANUALS_DIR="$($PKG_CONFIG osmo-gsm-manuals --variable=osmogsmmanualsdir 2>/dev/null)"
		if test -n "$OSMO_GSM_MANUALS_DIR"; then
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from pkg-conf)"
		else
			OSMO_GSM_MANUALS_DIR="../osmo-gsm-manuals"
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (fallback)"
		fi
	fi
	if ! test -d "$OSMO_GSM_MANUALS_DIR"; then
		AC_MSG_ERROR("OSMO_GSM_MANUALS_DIR does not exist! Install osmo-gsm-manuals or set OSMO_GSM_MANUALS_DIR.")
	fi

	# Find and run check-depends
	CHECK_DEPENDS="$OSMO_GSM_MANUALS_DIR/check-depends.sh"
	if ! test -x "$CHECK_DEPENDS"; then
		CHECK_DEPENDS="osmo-gsm-manuals-check-depends"
	fi
	if ! $CHECK_DEPENDS; then
		AC_MSG_ERROR("missing dependencies for --enable-manuals")
	fi

	# Put in Makefile with absolute path
	OSMO_GSM_MANUALS_DIR="$(realpath "$OSMO_GSM_MANUALS_DIR")"
	AC_SUBST([OSMO_GSM_MANUALS_DIR])
fi

# https://www.freedesktop.org/software/systemd/man/daemon.html
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 doc/examples/Makefile
                 ggsn/Makefile
                 gtp/Makefile
                 lib/Makefile
                 intl/Makefile
                 po/Makefile
                 utils/Makefile
                 sgsnemu/Makefile
                 doc/manuals/Makefile
                 contrib/Makefile
                 contrib/systemd/Makefile
                 tests/Makefile
                 tests/lib/Makefile
                 tests/gtp/Makefile
                 include/Makefile
                 include/osmocom/Makefile
                 include/osmocom/gtp/Makefile
                 libgtp.pc])
AC_OUTPUT

echo "
osmo-ggsn Configuration:
  GTP Linux kernel support:			${enable_gtp_linux}"
