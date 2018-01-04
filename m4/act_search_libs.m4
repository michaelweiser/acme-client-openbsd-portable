# clone of AC_SEARCH_LIBS but with a complete program so that definitions from
# headers can influence symbol names
#
# ACT_SEARCH_LIBS(FUNCTION, PROLOGUE, BODY, SEARCH-LIBS,
#                [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
#                [OTHER-LIBRARIES])
# --------------------------------------------------------
# Search for a library defining FUNC, if it's not already available.
AC_DEFUN([ACT_SEARCH_LIBS],
[AS_VAR_PUSHDEF([ac_Search], [ac_cv_search_$1])dnl
AC_CACHE_CHECK([for library containing $1], [ac_Search],
[ac_func_search_save_LIBS=$LIBS
AC_LANG_CONFTEST([AC_LANG_PROGRAM([$2], [$3])])
for ac_lib in '' $4; do
  if test -z "$ac_lib"; then
    ac_res="none required"
  else
    ac_res=-l$ac_lib
    LIBS="-l$ac_lib $7 $ac_func_search_save_LIBS"
  fi
  AC_LINK_IFELSE([], [AS_VAR_SET([ac_Search], [$ac_res])])
  AS_VAR_SET_IF([ac_Search], [break])
done
AS_VAR_SET_IF([ac_Search], , [AS_VAR_SET([ac_Search], [no])])
rm conftest.$ac_ext
LIBS=$ac_func_search_save_LIBS])
AS_VAR_COPY([ac_res], [ac_Search])
AS_IF([test "$ac_res" != no],
  [test "$ac_res" = "none required" || LIBS="$ac_res $LIBS"
  $5],
      [$6])
AS_VAR_POPDEF([ac_Search])dnl
])

# check for presence of a function like AC_CHECK_FUNC but using features of
# above ACT_SEARCH_LIBS
AC_DEFUN([ACT_SEARCH_LIBS_HAVE],
	[AH_TEMPLATE(AS_TR_CPP([HAVE_$1]),
		[Define to 1 if you have the `$1' function.])
	ACT_SEARCH_LIBS([$1], [$2], [$3], [$4],
		[AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_]$1))])])
