PKG_CHECK_MODULES([libcrypto], [libcrypto >= 2.4.0])
PKG_CHECK_MODULES([libtls], [libtls >= 2.4.0])
AS_IF([test "x$with_seccomp" != xno],
	[PKG_CHECK_MODULES([libseccomp], [libseccomp],
		[AC_DEFINE([HAVE_LIBSECCOMP],[1],
			[define if you have the seccomp library installed])],
		[AS_IF([test "x$with_seccomp" != xcheck],
			[AC_MSG_FAILURE(
				[--with-seccomp was given, but libseccomp was not found])])])])
