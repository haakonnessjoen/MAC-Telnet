#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([mactelnet],[1.0.0],[haakon.nessjoen@gmail.com])
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

AC_CHECK_LIB([rt], [nanosleep])
AC_CHECK_LIB([intl], [nanosleep])

# Use pkg-config to check for libcrypto, if available
# Otherwise, fall back to AC_SEARCH_LIBS
m4_ifdef([PKG_PROG_PKG_CONFIG], [
  # pkg-config is installed, use it to check for libcrypto
  PKG_PROG_PKG_CONFIG
  PKG_CHECK_MODULES([crypto], [libcrypto >= 1.1.0], [], [
    AC_SEARCH_LIBS([EVP_MD_CTX_new], [crypto], [], [AC_MSG_FAILURE([can't find openssl >= 1.1.0 crypto lib])])
  ])
], [
    AC_SEARCH_LIBS([EVP_MD_CTX_new], [crypto], [], [AC_MSG_FAILURE([can't find openssl >= 1.1.0 crypto lib])])
])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h float.h libintl.h locale.h netinet/in.h paths.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h termios.h unistd.h utmp.h utmpx.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([getrandom arc4random alarm bzero clock_gettime getpass gettimeofday inet_ntoa memset select setenv setlocale socket strcasecmp strerror strncasecmp sysinfo uname])

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile config/Makefile po/Makefile.in])
AC_OUTPUT
