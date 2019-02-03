/* unveil.c */

#include "config.h"

#ifndef HAVE_UNVEIL
int unveil(const char *path, const char *permissions) {
	return 0;
}
#endif
