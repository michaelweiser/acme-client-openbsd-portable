# check for presence of a function much like AC_CHECK_FUNCS but with a complete
# program so that definitions from headers can influence symbol names
AC_DEFUN([ACT_CHECK_PROGRAM],
	[AH_TEMPLATE(AS_TR_CPP([HAVE_$1]),
		[Define to 1 if you have the `$1' function.])
	AS_VAR_PUSHDEF([ac_Have], [ac_cv_have_$1])
	AC_CACHE_CHECK([whether $1 exists],
		[ac_Have],
		[AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([$2], [$3])],
			[AS_VAR_SET([ac_Have], [yes])],
			[AS_VAR_SET([ac_Have], [no])])])
	AS_VAR_COPY([ac_res], [ac_Have])
	AS_IF([test "$ac_res" = yes],
		[AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_]$1))
		$4],
		[$5])])
