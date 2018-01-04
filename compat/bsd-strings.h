#ifndef ACME_CLIENT_STRINGS_H
#define ACME_CLIENT_STRINGS_H

#include "config.h"

#include <strings.h>

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *, size_t);
#endif

#endif /* ACME_CLIENT_STRINGS_H */
