/* unveil.c */

#include "config.h"

#ifndef HAVE_UNVEIL
#include "bsd-stdlib.h"
#include "pledge.h"

int unveil(const char *path, const char *permissions) {
#ifdef HAVE_LIBSANDBOX
	/* TODO: permission + multiple paths */
	if (seatbelt_add_param("unveil-path", path) == -1)
		return -1;
#endif /* HAVE_LIBSANDBOX */

	return 0;
}
#endif /* HAVE_UNVEIL */
