#ifndef ACME_CLIENT_PLEDGE_H
#define ACME_CLIENT_PLEDGE_H

#include "config.h"

#ifdef HAVE_LIBSANDBOX
#define chngproc chngproc_intercept
#define fileproc fileproc_intercept

int chngproc_intercept(int, const char *);
int fileproc_intercept(int, const char *, const char *, const char *, const
		char *);
int seatbelt_add_param(const char *, const char *);
#endif /* HAVE_LIBSANDBOX */

#endif /* ACME_CLIENT_PLEDGE_H */
