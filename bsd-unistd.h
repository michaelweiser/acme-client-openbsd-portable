#ifndef ACME_CLIENT_UNISTD_H
#define ACME_CLIENT_UNISTD_H

#include "config.h"

#include <unistd.h>

#include "bsd-setres_id.h"

#ifndef HAVE_PLEDGE
int pledge(const char *, const char *);
#endif

#ifndef HAVE_UNVEIL
int unveil(const char *, const char *);
#endif

#endif /* ACME_CLIENT_UNISTD_H */
