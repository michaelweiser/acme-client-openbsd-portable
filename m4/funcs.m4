# vasprintf is used by asprintf replacement
# memset_s is used by explicit_bzero replacement
AC_CHECK_FUNCS([vasprintf memset_s setreuid setregid])

AC_CHECK_FUNCS([setresuid], [
	dnl Some platorms have setresuid that isn't implemented, test for this
	AC_MSG_CHECKING([if setresuid seems to work])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <errno.h>
		]], [[
	errno=0;
	setresuid(0,0,0);
	if (errno==ENOSYS)
		exit(1);
	else
		exit(0);
		]])],
		[AC_MSG_RESULT([yes])],
		[AC_DEFINE([BROKEN_SETRESUID], [1],
			[Define if your setresuid() is broken])
		 AC_MSG_RESULT([not implemented])],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])
AS_IF([test "x$ac_cv_func_setresuid" = xno], [AC_LIBOBJ([bsd-setres_id])])

AC_CHECK_FUNCS([setresgid], [
	dnl Some platorms have setresgid that isn't implemented, test for this
	AC_MSG_CHECKING([if setresgid seems to work])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <errno.h>
		]], [[
	errno=0;
	setresgid(0,0,0);
	if (errno==ENOSYS)
		exit(1);
	else
		exit(0);
		]])],
		[AC_MSG_RESULT([yes])],
		[AC_DEFINE([BROKEN_SETRESGID], [1],
			[Define if your setresgid() is broken])
		 AC_MSG_RESULT([not implemented])],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])
AS_IF([test "x$ac_cv_func_setresgid" = xno], [AC_LIBOBJ([bsd-setres_id])])

# we always use the openssh version of asprintf because it
# deterministically NULLs the return pointer if memory allocation
# fails. Other variants leave it in undefined state which the OpenBSD
# source may not expect.
AC_LIBOBJ([bsd-asprintf])
AC_REPLACE_FUNCS([pledge reallocarray recallocarray strtonum strlcat strlcpy])

ACT_SEARCH_LIBS_HAVE([__b64_ntop],
	[[#include <resolv.h>]],
	[[__b64_ntop(NULL, 0, NULL, 0);]],
	[resolv])
ACT_SEARCH_LIBS_HAVE([b64_ntop],
	[[#include <resolv.h>]],
	[[b64_ntop(NULL, 0, NULL, 0);]],
	[resolv])
AS_IF([test "x$ac_cv_search___b64_ntop" != xno],[],
	[test "x$ac_cv_search_b64_ntop" != xno],[],
	[AC_LIBOBJ([b64_ntop])])
ACT_CHECK_PROGRAM([va_copy],
	[[#include <stdarg.h>
		va_list x,y;]],
	[[va_copy(x, y);]])
ACT_CHECK_PROGRAM([__va_copy],
	[[#include <stdarg.h>
		va_list x,y;]],
	[[__va_copy(x, y);]])
AC_CHECK_FUNCS([setprogname],[],
	[AC_LIBOBJ([setprogname])
	 ACT_CHECK_PROGRAM([__progname],
		[[extern char *__progname;]],
		[[printf("%s", __progname);]])])

# statically disable b64_pton in b64_ntop.c because we do not need it
AC_DEFINE([HAVE_B64_PTON],[1],[not needed])

# compatibility with older bison (e.g. 2.3 on Darwin)
AC_DEFINE([YYSTYPE_IS_DECLARED],[1],[old bison])

# check if libtls has tls_default_ca_cert_file and warn if the user wants to
# override the default CA file while it is in use, provide an alternative
# implementation otherwise
act_save_CFLAGS="$CFLAGS"
act_save_LIBS="$LIBS"
CFLAGS="$CFLAGS $libtls_CFLAGS"
LIBS="$LIBS $libtls_LIBS"
AC_CHECK_FUNCS([tls_default_ca_cert_file],
	[AS_IF([test "${with_default_ca_file+set}" = set],
		[AC_MSG_WARN([tls_default_ca_cert_file of libressl is in use.
	--with-default-ca-file will have no effect.
	Please configure libressl accordingly instead.])])],
	[AC_LIBOBJ([tls_default_ca_cert_file])
	 AS_IF([test "${with_default_ca_file+set}" = set],[],
		[AC_MSG_NOTICE([Using CA certificate bundle at $defaultcafile.
	Reconfigure with --with-default-ca-file as necessary.])])])
CFLAGS="$act_save_CFLAGS"
LIBS="$act_save_LIBS"
