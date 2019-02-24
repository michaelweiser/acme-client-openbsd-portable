#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([acme-client], [0.4], [https://github.com/michaelweiser/acme-client-openbsd-portable.git])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
m4_include([m4/act_search_libs.m4])
m4_include([m4/act_check_program.m4])
m4_include([m4/args.m4])
AC_CONFIG_SRCDIR([json.c])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS
AX_CFLAGS_WARN_ALL

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_YACC
PKG_PROG_PKG_CONFIG

# Checks for libraries.
m4_include([m4/libs.m4])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/param.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([getpagesize memset realpath socket strchr strdup strerror strndup strrchr strstr])
m4_include([m4/funcs.m4])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
