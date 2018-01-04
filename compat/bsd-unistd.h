#ifndef ACME_CLIENT_UNISTD_H
#define ACME_CLIENT_UNISTD_H

#include "config.h"

#include <unistd.h>

#ifndef HAVE_PLEDGE
int pledge(const char *, const char *);
#endif

#endif /* ACME_CLIENT_UNISTD_H */
