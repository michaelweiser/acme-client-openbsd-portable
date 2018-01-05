AC_ARG_WITH([default-ca-file],
	[AS_HELP_STRING([--with-default-ca-file=DIR],
		[default ca certificate bundle])],
		[defaultcafile=$withval],
		[defaultcafile=/etc/ssl/cert.pem])
AC_SUBST([defaultcafile], [$defaultcafile])
AC_ARG_WITH([www-dir],
	[AS_HELP_STRING([--with-www-dir=DIR],
		[default challenge directory])],
		[wwwdir=$withval],
		[wwwdir=/var/www/acme])
AC_SUBST([wwwdir], [$wwwdir])
AC_ARG_WITH([privsep-path],
	[AS_HELP_STRING([--with-privsep-path=DIR],
		[privilege separation directory])],
		[privseppath=$withval],
		[privseppath=/var/empty])
AC_SUBST([privseppath], [$privseppath])
AC_ARG_WITH([privsep-user],
	[AS_HELP_STRING([--with-privsep-user=DIR],
		[privilege separation user])],
		[privsepuser=$withval],
		[privsepuser=nobody])
AC_SUBST([privsepuser], [$privsepuser])

AC_ARG_WITH([seccomp],
	[AS_HELP_STRING([--with-seccomp],
		[enable seccomp syscall filtering @<:@default=check@:>@])],
		[],
		[with_seccomp=check])
