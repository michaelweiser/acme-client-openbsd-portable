#!/bin/sh

set -e

version=0.1

srcdir=$PWD
upstream=anoncvs@anoncvs.ca.openbsd.org:/cvs
openssh=https://github.com/openssh/openssh-portable.git
acarchive=git://git.sv.gnu.org/autoconf-archive.git

obsd=/tmp/openbsd
if ! [ -e "$obsd" ] ; then
	mkdir "$obsd"
	cd "$obsd"
	cvs -qd "$upstream" checkout -P src/etc/acme-client.conf
	cvs -qd "$upstream" checkout -P src/usr.sbin/acme-client
	find "$obsd" -name CVS -prune -exec rm -rf {} \;
	cd "$srcdir"
fi

# copy over the source
cp "$obsd"/src/etc/acme-client.conf "$srcdir"
cp "$obsd"/src/usr.sbin/acme-client/* "$srcdir"

# redirect some includes to augmented ones with additional definitions and
# inclusion of bsdlib variants, others directly to the bsdlib versions
for i in *.[chy] ; do
	sed -e 's,<stdlib\.h>,"bsd-stdlib.h",g' \
		-e 's,<unistd\.h>,"bsd-unistd.h",g' \
		-e 's,<err\.h>,"bsd/err.h",g' \
		-e 's,<stdio\.h>,"bsd/stdio.h",g' \
		-e 's,<string\.h>,"bsd/string.h",g' \
		-e 's,<sys/queue\.h>,"bsd/sys/queue.h",g' \
		$i > $i.tmp
	mv $i.tmp $i
done

# have all files source config.h
for i in *.[chy] ; do
	awk '/^#include/ && !x { print "#include \"config.h\""  ; x=1 } 1' $i > $i.tmp
	mv $i.tmp $i
done

os=/tmp/openssh
[ -e "$os" ] || \
	git clone --depth=1 "$openssh" "$os"

# get some BSD functions that aren't in libbsd
cp "$os"/openbsd-compat/base64.c b64_ntop.c
cp "$os"/openbsd-compat/base64.h b64_ntop.h
cp "$os"/openbsd-compat/bsd-asprintf.c asprintf.c
cp "$os"/openbsd-compat/re{,c}allocarray.c .

# make openssh bits include our config.h instead of theis includes.h
for i in b64_ntop.[ch] asprintf.c re{,c}allocarray.* ; do
	sed -e "/include.*includes\.h/s/includes\.h/config.h/" \
		$i > $i.tmp
	mv $i.tmp $i
done

# install our own glue
cp compat/* .

# patch
for i in patches/* ; do
	patch -p0 < $i
done

# turn Makefile into an automake template
sed -e "/include <bsd.prog.mk>/d" \
	-e "/^[YC]FLAGS/d" \
	-e "/^DPADD/d" \
	-e "/^LDADD/d" \
	-e "s/^PROG/bin_PROGRAMS /" \
	-e "s/^SRCS/acme_client_SOURCES /" \
	-e "s/^MAN/dist_man_MANS /" \
	Makefile > Makefile.am
rm -f Makefile

cat <<EOF >> Makefile.am
dist_sysconf_DATA = acme-client.conf
acme_client_CFLAGS = \$(WARN_CFLAGS) \$(LIBBSD_CFLAGS) \$(LIBTLS_CFLAGS) \$(LIBCRYPTO_CFLAGS)
acme_client_LDFLAGS = \$(WARN_LDFLAGS)
acme_client_LDADD = \$(LIBBSD_LIBS) \$(LIBTLS_LIBS) \$(LIBCRYPTO_LIBS)
EOF

# generate a configure.ac skeleton
autoscan

# adjust configure.ac skeleton to final product
awk -v version=$version -v bugurl=foo \
'/^AC_INIT/ {
	gsub(/FULL-PACKAGE-NAME/, "acme-client", $0);
	gsub(/VERSION/, version, $0);
	gsub(/BUG-REPORT-ADDRESS/, bugurl, $0);
	print;
	print("AM_INIT_AUTOMAKE([foreign -Wall -Werror])");
	next;
}
/^AC_CONFIG_HEADERS/ {
	print;

	# get EAI_NODATA defined on Linux through -D_GNU_SOURCE
	print("AC_USE_SYSTEM_EXTENSIONS" RS \
		"AX_CFLAGS_WARN_ALL");
	next;
}
/^AC_PROG_CC/ {
	print($0 RS \
		"AC_PROG_YACC" RS \
		"PKG_PROG_PKG_CONFIG");
	next;
}
/^# Checks for libraries/ {
	print($0 RS \
		"PKG_CHECK_MODULES([LIBBSD], [libbsd >= 0.7.0])" RS \
		"PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto >= 2.4.0])" RS \
		"PKG_CHECK_MODULES([LIBTLS], [libtls >= 2.4.0])");
	next;
}
/^AC_CHECK_HEADERS/ {
	print;

	# parse.c
	print("AC_CHECK_HEADERS([libintl.h malloc.h])");
	next;
}
/^AC_CHECK_FUNCS/ {
	print

	# parse.c
	print("AC_FUNC_ALLOCA");

	# we always use the openssh version of asprintf because it
	# deterministically NULLs the return pointer if memory allocation
	# fails. Other variants leave it in undefined state which the OpenBSD
	# source may not expect.
	print("AC_LIBOBJ([asprintf])");

	print("AH_TEMPLATE([HAVE_PLEDGE])" RS \
		"AC_SEARCH_LIBS([pledge]," RS \
		"	[bsd]," RS \
		"	[AC_DEFINE([HAVE_PLEDGE],[1])])");
	print("AH_TEMPLATE([HAVE_REALLOCARRAY])" RS \
		"AC_SEARCH_LIBS([reallocarray]," RS \
		"	[bsd]," RS \
		"	[AC_DEFINE([HAVE_REALLOCARRAY],[1])]," RS \
		"	[AC_LIBOBJ([reallocarray])])");
	print("AH_TEMPLATE([HAVE_RECALLOCARRAY])" RS \
		"AC_SEARCH_LIBS([recallocarray]," RS \
		"	[bsd]," RS \
		"	[AC_DEFINE([HAVE_RECALLOCARRAY],[1])]," RS \
		"	[AC_LIBOBJ([recallocarray])])");
	print("AH_TEMPLATE([HAVE___B64_NTOP])" RS \
		"AC_SEARCH_LIBS([__b64_ntop]," RS \
		"	[bsd resolv]," RS \
		"	[AC_DEFINE([HAVE___B64_NTOP],[1])])" RS \
		"AH_TEMPLATE([HAVE_B64_NTOP])" RS \
		"AC_SEARCH_LIBS([b64_ntop]," RS \
		"	[bsd resolv]," RS \
		"	[AC_DEFINE([HAVE_B64_NTOP],[1])])" RS \
		"if test $ac_cv_search___b64_ntop = no && test $ac_cv_search_b64_ntop != no ; then" RS \
		"	AC_LIBOBJ([b64_ntop])" RS \
		"fi");

	# statically disable b64_pton in b64_ntop.c because we do not need it
	printf("AC_DEFINE([HAVE_B64_PTON],[1]," RS \
		"	[we do not need b64_pton of or replacement library])");
	next;
} 1' configure.scan > configure.ac
rm -f configure.scan autoscan*.log

autoreconf -i -f
