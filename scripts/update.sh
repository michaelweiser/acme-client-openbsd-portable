#!/bin/sh

set -e

version=0.1
bugurl=https://github.com/michaelweiser/acme-client-openbsd-portable.git

srcdir=$PWD
upstream=anoncvs@anoncvs.ca.openbsd.org:/cvs
openssh=https://github.com/openssh/openssh-portable.git
acarchive=git://git.sv.gnu.org/autoconf-archive.git

obsd=/tmp/openbsd
if ! [ -e "$obsd" ] ; then
	mkdir "$obsd"
	cd "$obsd"
	cvs -qd "$upstream" checkout -P \
		src/etc/acme-client.conf \
		src/usr.sbin/acme-client \
		src/sys/sys/pledge.h
	find "$obsd" -name CVS -prune -exec rm -rf {} \;
	cd "$srcdir"
fi

# copy over the source
cp "$obsd"/src/etc/acme-client.conf "$srcdir"
cp "$obsd"/src/usr.sbin/acme-client/* "$srcdir"
cp "$obsd"/src/sys/sys/pledge.h "$srcdir"/bsd-sys-pledge.h

os=/tmp/openssh
[ -e "$os" ] || \
	git clone --depth=1 "$openssh" "$os"

# get some BSD functions that aren't typically available on non-BSD systems
sed "/include.*base64\.h/s/base64\.h/b64_ntop.h/" \
	"$os"/openbsd-compat/base64.c > b64_ntop.c
cp "$os"/openbsd-compat/base64.h b64_ntop.h
sed -e "s/error(/warnx(/" \
	-e '/include.*log\.h/s/log\.h/err.h/' \
	-e "/include.*sys\/types\.h/a\\
#include <errno.h>" \
	"$os"/openbsd-compat/bsd-setres_id.c > bsd-setres_id.c
cp "$os"/openbsd-compat/sys-queue.h bsd-sys-queue.h

for i in bsd-asprintf.c bsd-setres_id.h \
		strtonum.c strlcat.c strlcpy.c \
		reallocarray.c recallocarray.c \
		explicit_bzero.c ; do
	cp "$os"/openbsd-compat/$i .
done

# make openssh bits include our config.h instead of theis includes.h
for i in b64_ntop.[ch] \
		bsd-asprintf.c bsd-setres_id.c \
		strtonum.c strlcat.c strlcpy.c \
		reallocarray.c recallocarray.c \
		explicit_bzero.c ; do
	sed -e "/include.*includes\.h/s/includes\.h/config.h/" \
		$i > $i.tmp
	mv $i.tmp $i
done

# redirect some includes to augmented ones with additional definitions
for i in *.[chy] ; do
	sed -e 's,<stdlib\.h>,"bsd-stdlib.h",g' \
		-e 's,<string\.h>,"bsd-string.h",g' \
		-e 's,<strings\.h>,"bsd-strings.h",g' \
		-e 's,<unistd\.h>,"bsd-unistd.h",g' \
		-e 's,<stdarg\.h>,"bsd-stdarg.h",g' \
		-e 's,<resolv\.h>,"bsd-resolv.h",g' \
		-e 's,<sys/queue\.h>,"bsd-sys-queue.h",g' \
		$i > $i.tmp
	mv $i.tmp $i
done

# have all files source config.h if not already present
for i in *.[chy] ; do
	awk '/^#include.*\"config\.h\"/ { x=1 }
		/^#include/ && !x { print "#include \"config.h\""  ; x=1 } 1' \
			$i > $i.tmp
	mv $i.tmp $i
done

# install our own glue
cp compat/* .

# patch
for i in patches/*.patch ; do
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
acme_client_SOURCES += $(echo *.h | sed -e "s/ config.h / /g")

# AM_CPPFLAGS so it also applies to LIBOBJS
AM_CPPFLAGS = -DCONF_FILE='"\$(sysconfdir)/acme-client.conf"' \\
	-DWWW_DIR='"\$(wwwdir)"' \\
	-DPRIVSEP_PATH='"\$(privseppath)"' \\
	-DPRIVSEP_USER='"\$(privsepuser)"' \\
	-DDEFAULT_CA_FILE='"\$(defaultcafile)"'

dist_sysconf_DATA = acme-client.conf
acme_client_CFLAGS = \$(WARN_CFLAGS) \$(LIBTLS_CFLAGS) \$(LIBCRYPTO_CFLAGS)
acme_client_LDFLAGS = \$(WARN_LDFLAGS)
acme_client_LDADD = \$(LIBOBJS) \$(LIBTLS_LIBS) \$(LIBCRYPTO_LIBS)
EOF

# generate a configure.ac skeleton
rm -f configure.ac
autoscan

# adjust configure.ac skeleton to final product
awk -v version=$version -v bugurl=$bugurl \
'/^AC_INIT/ {
	gsub(/FULL-PACKAGE-NAME/, "acme-client", $0);
	gsub(/VERSION/, version, $0);
	gsub(/BUG-REPORT-ADDRESS/, bugurl, $0);
	print($0 RS \
		"AM_INIT_AUTOMAKE([foreign -Wall -Werror])" RS \
		"m4_include([m4/act_search_libs.m4])" RS \
		"m4_include([m4/act_check_program.m4])" RS \
		"m4_include([m4/args.m4])");
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
		"PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto >= 2.4.0])" RS \
		"PKG_CHECK_MODULES([LIBTLS], [libtls >= 2.4.0])");
	next;
}
/^AC_CHECK_FUNCS/ {
	print($0 RS "m4_include([m4/funcs.m4])");
	next;
}
# we assume some functions to be present and working
#/^AC_FUNC_ALLOCA/ { next; }
/^AC_FUNC_MALLOC/ { next; }
/^AC_FUNC_REALLOC/ { next; }
/^AC_FUNC_MKTIME/ { next; }
1' configure.scan > configure.ac
rm -f configure.scan autoscan*.log

autoreconf -i -f
