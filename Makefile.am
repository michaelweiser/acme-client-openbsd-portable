#	$OpenBSD: Makefile,v 1.9 2019/06/12 11:09:25 gilles Exp $
bin_PROGRAMS =		acme-client
acme_client_SOURCES =		acctproc.c base64.c certproc.c chngproc.c dbg.c dnsproc.c
acme_client_SOURCES +=		fileproc.c http.c jsmn.c json.c keyproc.c main.c netproc.c
acme_client_SOURCES +=		parse.y revokeproc.c key.c util.c

dist_man_MANS =		acme-client.1 acme-client.conf.5



acme_client_SOURCES += b64_ntop.h bsd-resolv.h bsd-setres_id.h bsd-stdarg.h bsd-stdlib.h bsd-string.h bsd-strings.h bsd-sys-pledge.h bsd-sys-queue.h bsd-unistd.h extern.h http.h jsmn.h key.h libressl-tls.h parse.h pledge.h vis.h

AM_CFLAGS = -DCONF_FILE='"$(sysconfdir)/acme-client.conf"' \
	-DWWW_DIR='"$(wwwdir)"' \
	-DPRIVSEP_PATH='"$(privseppath)"' \
	-DPRIVSEP_USER='"$(privsepuser)"' \
	-DDEFAULT_CA_FILE='"$(defaultcafile)"' \
	$(WARN_CFLAGS) \
	$(libtls_CFLAGS) $(libcrypto_CFLAGS) \
	$(libseccomp_CFLAGS)

dist_sysconf_DATA = acme-client.conf
acme_client_LDFLAGS = $(WARN_LDFLAGS)
acme_client_LDADD = $(LIBOBJS) \
	$(libtls_LIBS) $(libcrypto_LIBS) \
	$(libseccomp_LIBS)
