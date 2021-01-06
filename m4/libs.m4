PKG_CHECK_MODULES([libcrypto], [libcrypto >= 1.0.1])
PKG_CHECK_MODULES([libtls], [libtls >= 2.4.0])
AS_IF([test "x$with_seccomp" != xno],
	[PKG_CHECK_MODULES([libseccomp], [libseccomp],
		[AC_DEFINE([HAVE_LIBSECCOMP],[1],
			[define if you have the seccomp library installed])],
		[AS_IF([test "x$with_seccomp" != xcheck],
			[AC_MSG_FAILURE(
				[--with-seccomp was given, but libseccomp was not found])])])])

# sandbox functions are accessible via libSystem but we need to explicitly link
# against libsandbox to avoid dlopen from inside chroot()
AS_IF([test "x$with_seatbelt" != xno],
	[AC_CHECK_LIB([sandbox],[[sandbox_init]],
		[],
		[AS_IF([test "x$with_seatbelt" != xcheck],
			[AC_MSG_FAILURE(
				[--with-seatbelt was given, but sandbox_init was not found])])])])
