#ifndef ACME_CLIENT_UNISTD_H
#define ACME_CLIENT_UNISTD_H

#include <bsd/unistd.h>

#ifndef HAVE_PLEDGE
/* pledge is highly OpenBSD-specific */
#define pledge(x, y) (0)
#endif

#endif /* ACME_CLIENT_UNISTD_H */
