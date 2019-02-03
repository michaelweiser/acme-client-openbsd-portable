#ifndef ACME_LIBRESSL_TLS_H
#define ACME_LIBRESSL_TLS_H

#include "config.h"

#include <tls.h>

#ifndef HAVE_TLS_DEFAULT_CA_CERT_FILE
const char *tls_default_ca_cert_file(void);
#endif

#endif /* ACME_LIBRESSL_TLS_H */
