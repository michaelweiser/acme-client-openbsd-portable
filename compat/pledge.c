/*	$OpenBSD: kern_pledge.c,v 1.226 2017/12/12 01:12:34 deraadt Exp $	*/

/*
 * OpenBSD:
 * Copyright (c) 2015 Nicholas Marriott <nicm@openbsd.org>
 * Copyright (c) 2015 Theo de Raadt <deraadt@openbsd.org>
 *
 * OpenSSH:
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#ifndef HAVE_PLEDGE

#include <stdint.h> /* uint64_t */
#include <errno.h> /* EINVAL */
#include <err.h> /* err() */
#include "bsd-stdlib.h" /* NULL */
#include "bsd-string.h" /* strrchr() */
#include "bsd-unistd.h" /* chroot() */

#include <pwd.h> /* getpwnam() */
#include <grp.h> /* setgroups() Linux */

#include "bsd-sys-pledge.h"

#include "extern.h" /* dodbg() */

/* acme-client uses only a few pledges. Deactivate the others so we bail if
 * upstream starts to use more */
static const struct {
	char *name;
	uint64_t flags;
} pledgereq[] = {
	/*{ "audio",		PLEDGE_AUDIO },
	{ "bpf",		PLEDGE_BPF },
	{ "chown",		PLEDGE_CHOWN | PLEDGE_CHOWNUID },*/
	{ "cpath",		PLEDGE_CPATH },
	/*{ "disklabel",		PLEDGE_DISKLABEL },*/
	{ "dns",		PLEDGE_DNS },
	/*{ "dpath",		PLEDGE_DPATH },
	{ "drm",		PLEDGE_DRM },
	{ "error",		PLEDGE_ERROR },
	{ "exec",		PLEDGE_EXEC },
	{ "fattr",		PLEDGE_FATTR | PLEDGE_CHOWN },
	{ "flock",		PLEDGE_FLOCK },
	{ "getpw",		PLEDGE_GETPW },
	{ "id",			PLEDGE_ID },*/
	{ "inet",		PLEDGE_INET },
	/*{ "mcast",		PLEDGE_MCAST },
	{ "pf",			PLEDGE_PF },
	{ "proc",		PLEDGE_PROC },
	{ "prot_exec",		PLEDGE_PROTEXEC },
	{ "ps",			PLEDGE_PS },
	{ "recvfd",		PLEDGE_RECVFD },
	{ "route",		PLEDGE_ROUTE },*/
	{ "rpath",		PLEDGE_RPATH },
	/*{ "sendfd",		PLEDGE_SENDFD },
	{ "settime",		PLEDGE_SETTIME },*/
	{ "stdio",		PLEDGE_STDIO },
	/*{ "tape",		PLEDGE_TAPE },
	{ "tmppath",		PLEDGE_TMPPATH },
	{ "tty",		PLEDGE_TTY },
	{ "unix",		PLEDGE_UNIX },
	{ "vminfo",		PLEDGE_VMINFO },
	{ "vmm",		PLEDGE_VMM },*/
	{ "wpath",		PLEDGE_WPATH },
};

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

void chroot_droppriv(uint64_t promises) {
	uid_t uid;
	gid_t gid;
	struct passwd *pwent;

	if (promises & PLEDGE_RPATH || promises & PLEDGE_WPATH) {
		/* processes which need to read or write stuff do their own
		 * chroot()ing and priv-dropping if possible or will
		 * come back again without those requests and will get
		 * sandboxed then. */
		return;
	}

	if ((pwent = getpwnam(PRIVSEP_USER)) == NULL)
		errx(EXIT_FAILURE, "unknown user: " PRIVSEP_USER);

	uid = pwent->pw_uid;
	gid = pwent->pw_gid;

	/* DNS resolution needs access to the actual /etc/resolv.conf.
	 * For the network process, chrooting only works because it is
	 * preloading the whole CA cert bundle at startup. It will not
	 * work with a CA path directory because certificate search is
	 * deferred until the TLS handshake. */
	if ((promises & PLEDGE_DNS) == 0) {
		if (chroot(PRIVSEP_PATH) != 0)
			err(EXIT_FAILURE, "chroot('" PRIVSEP_PATH "')");

		if (chdir("/") != 0)
			err(EXIT_FAILURE, "chdir('/')");
	}

	if (setgroups(1, &gid) != 0 ||
		setresgid(gid, gid, gid) != 0 ||
		setresuid(uid, uid, uid) != 0 )
		err(EXIT_FAILURE, "drop privileges");

	if (getgid() != gid || getegid() != gid)
		err(EXIT_FAILURE, "failed to drop gid");

	if (getuid() != uid || geteuid() != uid)
		err(EXIT_FAILURE, "failed to drop uid");
}

/* bsearch over pledgereq. return flags value if found, 0 else */
uint64_t
pledgereq_flags(const char *req_name)
{
	int base = 0, cmp, i, lim;

	for (lim = nitems(pledgereq); lim != 0; lim >>= 1) {
		i = base + (lim >> 1);
		cmp = strcmp(req_name, pledgereq[i].name);
		if (cmp == 0)
			return (pledgereq[i].flags);
		if (cmp > 0) { /* not found before, move right */
			base = i + 1;
			lim--;
		} /* else move left */
	}
	return (0);
}

int
parsepledges(const char *promises, u_int64_t *fp)
{
	char *rbuf, *rp, *pn;
	u_int64_t flags = 0, f;

	rbuf = strdup(promises);
	if (rbuf == NULL)
		return ENOMEM;

	for (rp = rbuf; rp && *rp; rp = pn) {
		pn = strchr(rp, ' ');	/* find terminator */
		if (pn) {
			while (*pn == ' ')
				*pn++ = '\0';
		}
		if ((f = pledgereq_flags(rp)) == 0) {
			free(rbuf);
			return EINVAL;
		}
		flags |= f;
	}
	free(rbuf);
	*fp = flags;
	return 0;
}

int
pledge(const char *p_req, const char *ep_req)
{
	uint64_t promises;

	/* bail if we start to see exec promises */
	if (ep_req != NULL) {
		errno = EINVAL;
		return -1;
	}

	if (parsepledges(p_req, &promises) != 0)  {
		errno = EINVAL;
		return -1;
	}

	dodbg("pledge: %s", p_req);

	/* portable chroot() and setuid(), does not return on error */
	chroot_droppriv(promises);

	return 0;
}
#endif
