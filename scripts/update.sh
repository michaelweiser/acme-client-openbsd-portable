#!/bin/sh

set -e

version=0.1
bugurl=https://github.com/michaelweiser/acme-client-openbsd-portable.git

srcdir=$PWD
upstream=anoncvs@anoncvs.ca.openbsd.org:/cvs
openssh=https://github.com/openssh/openssh-portable.git
acarchive=git://git.sv.gnu.org/autoconf-archive.git

tmpdir=$(mktemp -d)
echo "Staging update in $tmpdir..."

obsd="$(mktemp -d)"
echo "Checking out OpenBSD to $obsd..."
( cd "$obsd" &&
	cvs -qd "$upstream" checkout -P \
		src/etc/acme-client.conf \
		src/usr.sbin/acme-client \
		src/sys/sys/pledge.h )
find "$obsd" -name CVS -prune -exec rm -rf {} \;

# copy over the source
cp "$obsd"/src/etc/acme-client.conf "$tmpdir"
cp "$obsd"/src/usr.sbin/acme-client/* "$tmpdir"

# sys/cdefs.h seems unnecessary and is not provided by musl
sed -e "/include.*sys\/cdefs\.h/d" \
	"$obsd"/src/sys/sys/pledge.h > "$tmpdir"/bsd-sys-pledge.h

# done with OpenBSD
rm -rf "$obsd"

os="$(mktemp -d)"
echo "Checking out OpenSSH to $os..."
git clone --depth=1 "$openssh" "$os"

# get some BSD functions that aren't typically available on non-BSD systems
sed "/include.*base64\.h/s/base64\.h/b64_ntop.h/" \
	"$os"/openbsd-compat/base64.c > "$tmpdir"/b64_ntop.c
# uses types from sys/types
sed "/include.*includes\.h/a\\
#include <sys/types.h>\\
" \
	"$os"/openbsd-compat/base64.h > "$tmpdir"/b64_ntop.h
sed -e "s/error(/warnx(/" \
	-e '/include.*log\.h/s/log\.h/err.h/' \
	-e "/include.*sys\/types\.h/a\\
#include <errno.h>" \
	"$os"/openbsd-compat/bsd-setres_id.c > "$tmpdir"/bsd-setres_id.c
cp "$os"/openbsd-compat/sys-queue.h "$tmpdir"/bsd-sys-queue.h

for i in bsd-asprintf.c bsd-setres_id.h \
		strtonum.c strlcat.c strlcpy.c \
		reallocarray.c recallocarray.c \
		explicit_bzero.c ; do
	cp "$os"/openbsd-compat/$i "$tmpdir"
done

# done with OpenSSH
rm -rf "$os"

# make openssh bits include our config.h instead of their includes.h
# redirect some includes to augmented ones with additional definitions
# have all files source config.h if not already present
for i in "$tmpdir"/*.[chy] ; do
	sed -e 's,<stdlib\.h>,"bsd-stdlib.h",g' \
		-e 's,<string\.h>,"bsd-string.h",g' \
		-e 's,<strings\.h>,"bsd-strings.h",g' \
		-e 's,<unistd\.h>,"bsd-unistd.h",g' \
		-e 's,<stdarg\.h>,"bsd-stdarg.h",g' \
		-e 's,<resolv\.h>,"bsd-resolv.h",g' \
		-e 's,<sys/queue\.h>,"bsd-sys-queue.h",g' \
		-e "/include.*includes\.h/s/includes\.h/config.h/" \
		$i | \
	awk '/^#include.*\"config\.h\"/ { x=1 }
		/^#include/ && !x { print "#include \"config.h\""  ; x=1 } 1' \
		 > $i.tmp
	mv $i.tmp $i
done

# patch
for i in "$srcdir"/patches/*.patch ; do
	( cd "$tmpdir" &&
		patch -p0 --no-backup-if-mismatch < $i )
done

# turn Makefile into an automake template
sed -e "/include <bsd.prog.mk>/d" \
	-e "/^[YC]FLAGS/d" \
	-e "/^DPADD/d" \
	-e "/^LDADD/d" \
	-e "s/^PROG/bin_PROGRAMS /" \
	-e "s/^SRCS/acme_client_SOURCES /" \
	-e "s/^MAN/dist_man_MANS /" \
	"$tmpdir"/Makefile > "$tmpdir"/Makefile.am
rm -f "$tmpdir"/Makefile

# done staging
mv "$tmpdir"/* .
rm -rf "$tmpdir"

cat <<EOF >> Makefile.am
acme_client_SOURCES += $(echo *.h | sed -e "s/ config.h / /g")

# AM_CPPFLAGS so it also applies to LIBOBJS
AM_CPPFLAGS = -DCONF_FILE='"\$(sysconfdir)/acme-client.conf"' \\
	-DWWW_DIR='"\$(wwwdir)"' \\
	-DPRIVSEP_PATH='"\$(privseppath)"' \\
	-DPRIVSEP_USER='"\$(privsepuser)"' \\
	-DDEFAULT_CA_FILE='"\$(defaultcafile)"'

dist_sysconf_DATA = acme-client.conf
acme_client_CFLAGS = \$(WARN_CFLAGS) \\
	\$(libtls_CFLAGS) \$(libcrypto_CFLAGS) \\
	\$(libseccomp_CFLAGS)
acme_client_LDFLAGS = \$(WARN_LDFLAGS)
acme_client_LDADD = \$(LIBOBJS) \\
	\$(libtls_LIBS) \$(libcrypto_LIBS) \\
	\$(libseccomp_LIBS)
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
	print($0 RS "m4_include([m4/libs.m4])");
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
