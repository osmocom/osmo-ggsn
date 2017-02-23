# Process this file with autoconf to produce a configure script.
AC_INIT(openggsn, 0.93, laforge@gnumonks.org)
AC_CONFIG_SRCDIR([gtp/gtp.c])
AM_CONFIG_HEADER([config.h])
#AC_CONFIG_HEADER([config.h])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AC_CANONICAL_SYSTEM

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_CXX
LT_INIT

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

dnl GTP Linux kernel dependencies
AC_ARG_ENABLE([gtp-linux],
	AS_HELP_STRING([--enable-gtp-linux], [Build GTP tunneling Linux kernel]),
	[enable_gtp_linux="$enableval"], [enable_gtp_linux="no"])

AS_IF([test "x$enable_gtp_linux" = "xyes"], [
	PKG_CHECK_MODULES([LIBGTPNL], [libgtpnl >= 1.0.0])
])

AM_CONDITIONAL([ENABLE_GTP_KERNEL], [test "$enable_gtp_linux" = "yes"])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Check for if header
AC_CHECK_HEADERS([linux/if.h net/if.h])

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


# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
# AC_FUNC_MALLOC
# AC_FUNC_MEMCMP 
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset select socket strdup strerror strtol])
AC_CHECK_FUNCS(inet_aton inet_addr, break)

# check for getopt in standard library
adl_FUNC_GETOPT_LONG

AM_INIT_AUTOMAKE([foreign])

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.6.4)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMOCTRL, libosmoctrl)

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 ggsn/Makefile
                 gtp/Makefile
                 lib/Makefile
                 intl/Makefile
                 po/Makefile
                 sgsnemu/Makefile
                 tests/Makefile
                 libgtp.pc
                 openggsn.spec])
AC_OUTPUT

echo "
openggsn Configuration:
  GTP Linux kernel support:			${enable_gtp_linux}"
