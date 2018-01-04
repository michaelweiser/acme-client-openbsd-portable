#ifndef ACME_CLIENT_STRING_H
#define ACME_CLIENT_STRING_H

#include "config.h"

#include <string.h>

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#endif /* ACME_CLIENT_STRING_H */
