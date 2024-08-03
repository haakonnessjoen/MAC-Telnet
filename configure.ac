#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([mactelnet],[0.5.2],[haakon.nessjoen@gmail.com])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/mactelnet.c])
AC_CONFIG_HEADERS([src/config.h])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for libraries.
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19])

if test "x$GMSGFMT" = "x:"; then
  AC_MSG_ERROR([GNU gettext command line tools are required but not found.])
fi

AC_CHECK_HEADER([CoreFoundation/CoreFoundation.h],
  [
	have_corefoundation=true
	AC_SUBST([COREFOUNDATION_LIBS], ["-framework CoreFoundation"])
  ], [have_corefoundation=false]
)
AM_CONDITIONAL(HAVE_COREFOUNDATION, $have_corefoundation)

AC_CHECK_HEADER([SystemConfiguration/SystemConfiguration.h],
  [
	have_systemconfiguration=true
	AC_SUBST([SYSTEMCONFIGURATION_LIBS], ["-framework SystemConfiguration"])
  ], [have_systemconfiguration=false]
)
AM_CONDITIONAL(HAVE_SYSTEMCONFIGURATION, $have_systemconfiguration)

AC_CHECK_LIB([rt], [nanosleep])

# Use pkg-config to check for libcrypto, if available
# Otherwise, fall back to AC_SEARCH_LIBS
m4_ifdef([PKG_PROG_PKG_CONFIG], [
  # pkg-config is installed, use it to check for libcrypto
  PKG_PROG_PKG_CONFIG
  PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.1.0], [], [
    AC_SEARCH_LIBS([EVP_MD_CTX_new], [crypto], [], [AC_MSG_FAILURE([can't find openssl >= 1.1.0 crypto lib])])
  ])
], [
    AC_SEARCH_LIBS([EVP_MD_CTX_new], [crypto], [], [AC_MSG_FAILURE([can't find openssl >= 1.1.0 crypto lib])])
])

AC_ARG_WITH([config],
	[AS_HELP_STRING([--without-config], [don't install default config file])],
		[enable_config=$withval], [enable_config=yes])

AC_ARG_WITH([mactelnetd],
	[AS_HELP_STRING([--without-mactelnetd], [don't install mactelnetd binary])],
		[enable_mactelnetd=$withval], [enable_mactelnetd=yes])

AM_CONDITIONAL([INSTALL_CONFIG], [test x"$enable_config" != "xno" && test x"$enable_mactelnetd" != "xno"])
AM_CONDITIONAL([BUILD_MACTELNETD], [test x"$enable_mactelnetd" != "xno"])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h sys/random.h float.h libintl.h locale.h linux/netlink.h netinet/in.h paths.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h termios.h unistd.h utmp.h utmpx.h])

dnl check for readpassphrase. If none is found, we use getpass (with a warning)
AC_CHECK_HEADER([readpassphrase.h],
    [READPASSPHRASE=native],
    AC_CHECK_HEADER([bsd/readpassphrase.h],
        [READPASSPHRASE=bsd],
        [AC_MSG_WARN([falling back to obsoleted getpass(3)])]))

AS_IF([test "x$READPASSPHRASE" = "xnative"],[
    AC_DEFINE([HAVE_READPASSPHRASE], [1], [Enable readpassphrase])])

AS_IF([test "x$READPASSPHRASE" = "xbsd"],[
    AC_DEFINE([HAVE_BSDREADPASSPHRASE], [1], [Enable bsdreadpassphrase])
    AC_SEARCH_LIBS([readpassphrase], [bsd], [], [AC_MSG_ERROR([library for bsd/readpassphrase.h not found])])])

# Check if the target platform is macOS
case "$host_os" in
  darwin*)
    AC_CHECK_LIB([pthread], [pthread_create])

    AC_CHECK_LIB([intl], [libintl_gettext], [HAVE_LIBINTL=yes], [HAVE_LIBINTL=no])

    if test "$ac_cv_lib_pthread_pthread_create" = "yes"; then
        AC_SUBST([PTHREAD_LIBS], ["-lpthread"])
    else
        AC_MSG_ERROR([pthreads library not found])
    fi
    ;;
  *)
    ;;
esac

AM_CONDITIONAL([HAVE_LIBINTL], [test "x$HAVE_LIBINTL" = "xyes"])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([getrandom arc4random alarm bzero clock_gettime getpass gettimeofday inet_ntoa memset select setenv setlocale socket strcasecmp strerror strncasecmp sysinfo uname updwtmp updwtmpx])

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile config/Makefile po/Makefile.in])
AC_OUTPUT
