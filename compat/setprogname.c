#ifndef HAVE_SETPROGNAME
#include "bsd-stdlib.h"
#include <string.h>

#ifdef HAVE___PROGNAME
extern const char *__progname;
#endif

void setprogname(const char *progname) {
#ifdef HAVE___PROGNAME
	char *slash = strrchr(progname, '/');
	if (slash != NULL) {
		__progname = slash + 1;
	} else {
		__progname = progname;
	}
#endif
}
#endif
