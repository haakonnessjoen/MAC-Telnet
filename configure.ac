#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT(mactelnet, 0.4.4, haakon.nessjoen@gmail.com)
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
AC_CHECK_FUNCS([alarm bzero clock_gettime getpass gettimeofday inet_ntoa memset select setenv setlocale socket strcasecmp strerror strncasecmp sysinfo uname])

AC_OUTPUT(Makefile src/Makefile doc/Makefile config/Makefile po/Makefile.in)
