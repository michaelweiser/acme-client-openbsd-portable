#ifndef ACME_CLIENT_STDLIB_H
#define ACME_CLIENT_STDLIB_H

#include "config.h"

#include <stdlib.h>

#ifndef HAVE_ASPRINTF
int asprintf(char **, const char *, ...);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *, size_t, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *, long long, long long, const char **);
#endif

#endif /* ACME_CLIENT_STDLIB_H */
