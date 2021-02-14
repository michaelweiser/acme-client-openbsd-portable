/*
 * OpenBSD:
 * Copyright (c) 2015 Nicholas Marriott <nicm@openbsd.org>
 * Copyright (c) 2015 Theo de Raadt <deraadt@openbsd.org>
 *
 * OpenSSH:
 * Copyright (c) 1999-2004 Damien Miller <djm@mindrot.org>
 *
 * acme-client:
 * Copyright (c) 2016 Kristaps Dzonsons <kristaps@bsd.lv>
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
 *
 *	$OpenBSD: kern_pledge.c,v 1.226 2017/12/12 01:12:34 deraadt Exp $
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

/* #include "pledge.h" - must not be included here because it redirects
 * function calls to our interceptors by defining macros */

#ifdef HAVE_LIBSECCOMP
#include <seccomp.h>

/* headers for values in filters */
#include <signal.h> /* SIGPIPE */
#include <sys/socket.h> /* AF_{UNIX,INET,NETLINK}, SOL_IP/IP_RECVERR */
#include <netinet/in.h> /* sockaddr_{in,in6} */
#include <sys/un.h> /* sockaddr_un */
#include <sys/ioctl.h> /* FIONREAD */
#include <fcntl.h> /* O_RDWR */
#include <linux/netlink.h> /* sockaddr_nl */
#include <linux/futex.h> /* FUTEX_WAKE_PRIVATE */
#include <limits.h> /* LONG_MAX */
#endif /* HAVE_LIBSECCOMP */

#ifdef HAVE_LIBSANDBOX
#include <sys/stat.h> /* stat(), struct stat */
#endif /* HAVE_LIBSANDBOX */

#include "bsd-sys-pledge.h"

#include "extern.h" /* dodbg(), proccomp */

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
	{ "exec",		PLEDGE_EXEC },*/
	{ "fattr",		PLEDGE_FATTR | PLEDGE_CHOWN },
	/*{ "flock",		PLEDGE_FLOCK },
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

static void chroot_droppriv(uint64_t promises) {
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

#ifdef HAVE_LIBSECCOMP
static struct {
	const uint64_t promises;
	const uint32_t action;
	const char *syscall;
	const int arg_cnt;
	const struct scmp_arg_cmp args[3];
} scsb_calls[] = {
	{ PLEDGE_ALWAYS, SCMP_ACT_ALLOW, "exit", 0 },
	{ PLEDGE_ALWAYS, SCMP_ACT_ALLOW, "exit_group", 0 }, /* glibc */
	{ PLEDGE_ALWAYS, SCMP_ACT_ALLOW, "brk", 0 },
	/* glibc 2.28+ __pthread_once_slow */
	{ PLEDGE_ALWAYS, SCMP_ACT_ALLOW, "futex", 2,
		{ SCMP_A1(SCMP_CMP_EQ, FUTEX_WAKE_PRIVATE),
		  SCMP_A2(SCMP_CMP_EQ, (uint64_t)INT_MAX) }},

	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "fstat", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "lseek", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "read", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "readv", 0 }, /* musl */
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "write", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "writev", 0 }, /* musl */
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "close", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "getpid", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "getrandom", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "mmap", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "munmap", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "mprotect", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "nanosleep", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "wait4", 0 },
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "rt_sigaction", 1,
		{ SCMP_A0(SCMP_CMP_EQ, SIGPIPE) }},
	{ PLEDGE_STDIO, SCMP_ACT_ALLOW, "rt_sigreturn", 0 },

	/* order is important here: the first specification a pledge run runs
	 * into wins */
	{ PLEDGE_WPATH, SCMP_ACT_ALLOW, "open", 1,
		{ SCMP_A1(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_WRONLY) }},
	{ PLEDGE_WPATH, SCMP_ACT_ALLOW, "openat", 2, /* glibc 2.26+ */
		{ SCMP_A0(SCMP_CMP_EQ, (uint32_t)AT_FDCWD),
		  SCMP_A2(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_WRONLY) }},

	/*{ PLEDGE_RPATH, SCMP_ACT_ALLOW, "open", 1,
		{ SCMP_A1(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY) }},
	{ PLEDGE_RPATH, SCMP_ACT_ALLOW, "openat", 2,
		{ SCMP_A0(SCMP_CMP_EQ, (uint32_t)AT_FDCWD),
		  SCMP_A2(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY) }},*/

	/* /etc/resolv.conf */
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "open", 1,
		{ SCMP_A1(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "openat", 2, /* glibc 2.26+ */
		{ SCMP_A0(SCMP_CMP_EQ, (uint32_t)AT_FDCWD),
		  SCMP_A2(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "setsockopt", 2, /* glibc 2.30+ */
		{ SCMP_A1(SCMP_CMP_EQ, (uint32_t)IPPROTO_IP),
		  SCMP_A2(SCMP_CMP_EQ, (uint32_t)IP_RECVERR) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "setsockopt", 2, /* glibc 2.30+ */
		{ SCMP_A1(SCMP_CMP_EQ, (uint32_t)IPPROTO_IPV6),
		  SCMP_A2(SCMP_CMP_EQ, (uint32_t)IP_RECVERR) }},

	/* /etc/localtime, zoneinfo */
	{ PLEDGE_STDIO | PLEDGE_INET, SCMP_ACT_ERRNO(ENOENT), "open", 1,
		{ SCMP_A1(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY) }},
	{ PLEDGE_STDIO | PLEDGE_INET, SCMP_ACT_ERRNO(ENOENT), "openat", 2,
		{ SCMP_A0(SCMP_CMP_EQ, (uint32_t)AT_FDCWD), /* glibc 2.26+ */
		  SCMP_A2(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY) }},

	/* mkstemp */
	{ PLEDGE_RPATH | PLEDGE_WPATH, SCMP_ACT_ALLOW, "open", 1,
		{ SCMP_A1(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDWR) }},
	{ PLEDGE_RPATH | PLEDGE_WPATH, SCMP_ACT_ALLOW, "openat", 2,
		{ SCMP_A0(SCMP_CMP_EQ, (uint32_t)AT_FDCWD), /* glibc 2.26+ */
		  SCMP_A2(SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDWR) }},

	/* dns: resolver, inet: ACME */
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "socket", 3, /* IPv4 TCP */
		{ SCMP_A0(SCMP_CMP_EQ, AF_INET),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_STREAM, SOCK_STREAM),
		  SCMP_A2(SCMP_CMP_EQ, IPPROTO_IP) }},
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "socket", 3, /* IPv4 UDP */
		{ SCMP_A0(SCMP_CMP_EQ, AF_INET),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_DGRAM, SOCK_DGRAM),
		  SCMP_A2(SCMP_CMP_EQ, IPPROTO_IP) }},
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "socket", 3, /* IPv4 UDP */
		{ SCMP_A0(SCMP_CMP_EQ, AF_INET),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_DGRAM, SOCK_DGRAM),
		  SCMP_A2(SCMP_CMP_EQ, IPPROTO_UDP) }},
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "socket", 3, /* IPv6 TCP */
		{ SCMP_A0(SCMP_CMP_EQ, AF_INET6),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_STREAM, SOCK_STREAM),
		  SCMP_A2(SCMP_CMP_EQ, IPPROTO_IP) }},
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "socket", 3, /* IPv6 UDP */
		{ SCMP_A0(SCMP_CMP_EQ, AF_INET6),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_DGRAM, SOCK_DGRAM),
		  SCMP_A2(SCMP_CMP_EQ, IPPROTO_IP) }},
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "socket", 3, /* IPv6 UDP */
		{ SCMP_A0(SCMP_CMP_EQ, AF_INET6),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_DGRAM, SOCK_DGRAM),
		  SCMP_A2(SCMP_CMP_EQ, IPPROTO_UDP) }},
	/* TCP and glibc connect() of UDP socket to set default target */
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "connect", 1,
		{ SCMP_A2(SCMP_CMP_EQ, sizeof(struct sockaddr_in)) }},
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "connect", 1,
		{ SCMP_A2(SCMP_CMP_EQ, sizeof(struct sockaddr_in6)) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "poll", 0 },
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "bind", 1, /* DNS UDP */
		{ SCMP_A2(SCMP_CMP_EQ, sizeof(struct sockaddr_in)) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "bind", 1,
		{ SCMP_A2(SCMP_CMP_EQ, sizeof(struct sockaddr_in6)) }},
	/* glibc with connect(DGRAM, default target) */
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "sendto", 1,
		{ SCMP_A5(SCMP_CMP_EQ, 0) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "sendto", 1, /* musl */
		{ SCMP_A5(SCMP_CMP_EQ, sizeof(struct sockaddr_in)) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "sendto", 1,
		{ SCMP_A5(SCMP_CMP_EQ, sizeof(struct sockaddr_in6)) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "sendmmsg", 0 },
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "ioctl", 1,
		{ SCMP_A1(SCMP_CMP_EQ, FIONREAD) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "recvfrom", 0 },

	/* /etc/ld.so.nohwcap */
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ERRNO(ENOENT), "access", 0 },

	/* nscd unix domain socket */
	{ PLEDGE_DNS | PLEDGE_INET, SCMP_ACT_ALLOW, "socket", 2,
		{ SCMP_A0(SCMP_CMP_EQ, AF_UNIX),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_STREAM, SOCK_STREAM) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "connect", 1,
		{ SCMP_A2(SCMP_CMP_EQ, sizeof(struct sockaddr_un)) } },
	{ PLEDGE_INET, SCMP_ACT_ERRNO(ECONNREFUSED), "connect", 1,
		{ SCMP_A2(SCMP_CMP_EQ, sizeof(struct sockaddr_un)) } },

	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "fcntl", 2, /* /etc/hosts */
		{ SCMP_A1(SCMP_CMP_EQ, F_SETFD),
		  SCMP_A2(SCMP_CMP_EQ, FD_CLOEXEC) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "stat", 0 }, /* /etc/resolv.conf */

	/* AF_NETLINK getaddrinfo */
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "socket", 3,
		{ SCMP_A0(SCMP_CMP_EQ, AF_NETLINK),
		  SCMP_A1(SCMP_CMP_MASKED_EQ, SOCK_RAW, SOCK_RAW),
		  SCMP_A2(SCMP_CMP_EQ, NETLINK_ROUTE) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "bind", 1,
		{ SCMP_A2(SCMP_CMP_EQ, sizeof(struct sockaddr_nl)) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "getsockname", 0 },
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "sendto", 1,
		{ SCMP_A5(SCMP_CMP_EQ, sizeof(struct sockaddr_nl)) }},
	{ PLEDGE_DNS, SCMP_ACT_ALLOW, "recvmsg", 0 },

	{ PLEDGE_CPATH, SCMP_ACT_ALLOW, "link", 0 },
	{ PLEDGE_CPATH, SCMP_ACT_ALLOW, "unlink", 0 },
	{ PLEDGE_CPATH, SCMP_ACT_ALLOW, "rename", 0 },

	/* glibc 2.28+ qsort pagesize libressl */
	{ PLEDGE_INET, SCMP_ACT_ALLOW, "sysinfo", 0 },

	{ PLEDGE_FATTR, SCMP_ACT_ALLOW, "fchmod", 1,
		{ SCMP_A1(SCMP_CMP_MASKED_EQ, S_IRWXU|S_IRWXG|S_IRWXO,
					      S_IRUSR|S_IRGRP|S_IROTH) }},

};

static void
seccomp_violation(int signum, siginfo_t *info, void *ctx)
{
	char *syscall = seccomp_syscall_resolve_num_arch(info->si_arch,
			info->si_syscall);

	(void)signum;
	(void)ctx;

	if (syscall != NULL) {
		errx(EXIT_FAILURE, "seccomp, syscall: %s", syscall);
		free(syscall); /* not reached */
	}

	errx(EXIT_FAILURE, "seccomp, syscall: %d", info->si_syscall);
}

static void seccomp_sandbox(uint64_t promises, const enum comp proccomp) {
	struct sigaction act;
	sigset_t mask;
	scmp_filter_ctx ctx;
	int i;

	/* specifically ignore the first pledge call from netproc because it
	 * still needs to read stuff and will get back to us after */
	if ((proccomp == COMP_NET) && (promises & PLEDGE_RPATH))
		return;

	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &seccomp_violation;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSYS, &act, NULL) == -1)
		err(EXIT_FAILURE, "sigaction(SIGSYS)");
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
		err(EXIT_FAILURE, "sigprocmask(SIGSYS)");

	if ((ctx = seccomp_init(SCMP_ACT_TRAP)) == NULL)
		errx(EXIT_FAILURE, "seccomp_init");

	for (i = 0; i < nitems(scsb_calls); i++) {
		if ((scsb_calls[i].promises & promises) == 0)
			continue;

		switch (seccomp_rule_add_array(ctx,
				scsb_calls[i].action,
				seccomp_syscall_resolve_name(
					scsb_calls[i].syscall),
				scsb_calls[i].arg_cnt,
				scsb_calls[i].args)) {
			case 0:
			case -EEXIST:
				break;

			default:
				errx(EXIT_FAILURE, "seccomp_rule_add");
				break;
		}
	}

	// debug: seccomp_export_pfc(ctx, 2);
	if (seccomp_load(ctx) != 0) {
		seccomp_release(ctx);
		err(EXIT_FAILURE, "seccomp_load");
	}

	seccomp_release(ctx);
	return;
}
#endif

#ifdef HAVE_LIBSANDBOX
/* do not use sandbox.h because it'll spew deprecation warnings */
extern int sandbox_init_with_parameters(const char *, uint64_t, char **,
	char **);
int sandbox_check(pid_t pid, const char *, int type, ...);
extern void sandbox_free_error(char *);

static struct {
	const uint64_t comp;
	const char *profile;
} sb_profiles[] = {
	{ COMP__MAX,
		"(version 1)"
		"(deny default)"
		/* since /etc and /var are symlinks, basically everybody needs
		 * to be able to resolve them */
		"(allow file-read-metadata "
			"(require-any "
				"(literal \"/etc\")"
				"(literal \"/var\")"
			")"
		")"
	},

	{ COMP_CHALLENGE,
		/* funky behaviour: unlink() tries / of chroot first but then
		 * falls back to non-chroot path (at least as far as seatbelt
		 * is concerned). It seems we can deny from the root down to
		 * the challenge-dir to silence error logging on this and then
		 * allow again below the challenge dir. The two directives have
		 * to be in exactly that order for this to work as desired. */
		"(deny file-write-unlink (subpath \"/\")(with no-log))"
		"(allow file-write-create file-write-unlink "
			"(subpath (param \"challenge-dir\")))"
	},

	{ COMP_FILE, ""
		/* funkiness squared: file-write-create uses non-chroot path
		 * from the get-go and file-write-mode doesn't fall back to the
		 * non-chroot path. seatbelt doesn't seem well-tested with
		 * chroot(). */
		"(deny file-write-unlink (subpath \"/\")(with no-log))"
		"(define (root-dir-relative path-param) "
			"(string-append \"/\" (param path-param)))"
		"(define (cert-dir-relative path-param) "
			"(string-append "
				"(param \"cert-dir\") "
				"(root-dir-relative path-param)))"
		"(define (mkstemp-regex path) "
			"(regex "
				"(string-append "
					"\"^\" "
					"(regex-quote path) "
					"\"\\.[a-zA-Z0-9]+\")))"
		"(define (cert-file-allow path-param) "
			"(when (param path-param)"
				"(allow file-write-create file-write-unlink "
					"(require-any "
						/* the file itself */
						"(literal (cert-dir-relative path-param))"
						/* mkstemp() staging file */
						"(mkstemp-regex (cert-dir-relative path-param))"
					")"
				")"
				"(allow file-write-mode "
					"(require-any "
						/* the file itself */
						"(literal (root-dir-relative path-param))"
						/* mkstemp() staging file */
						"(mkstemp-regex (root-dir-relative path-param))"
					")"
				")"
			")"
		")"
		/* param cert-dir is always set but which of cert-file,
		 * chain-file and full-chain-file depends on configuration */
		"(cert-file-allow \"cert-file\")"
		"(cert-file-allow \"chain-file\")"
		"(cert-file-allow \"full-chain-file\")"
		//"(allow file-write-mode (subpath \"/\"))"
	},

	{ COMP_NET,
		/* first pledge */
		"(allow file-read-metadata (literal \"/private/etc/master.passwd\"))"
		"(allow file-read-data (literal \"/private/etc/master.passwd\"))"
		"(when (param \"unveil-path\")"
			"(allow file-read-data (literal (param \"unveil-path\")))"
		")"
		"(allow file-chroot (literal (param \"privsep-path\")))"
		/* second pledge */
		"(allow network-outbound (remote tcp4 \"*:443\"))"
		"(allow network-outbound (remote tcp4 \"*:80\"))"
	},

	{ COMP_DNS,
		"(deny sysctl-read (sysctl-name \"net.routetable.0.0.3.0\")(with no-log))"
		"(deny file-read-data "
			"(require-any "
				"(literal \"/dev/dtracehelper\")"
				"(literal \"/Library/Preferences/Logging/com.apple.diagnosticd.filter.plist\")"
				"(literal \"/dev/autofs_nowait\")"
			")"
			"(with no-log)"
		")"
		/* getaddrinfo -> mdns_attrinfo */
		"(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))"
		"(allow file-read-metadata "
			"(require-any "
				/* getaddrinfo -> mdns_attrinfo */
				/* getaddrinfo -> dyld -> libnetwork */
				"(literal \"/\")"
				"(literal \"/usr\")"
				"(regex #\"/usr/lib/[^/]*\\.dylib\")"
				"(regex #\"/usr/lib/system/[^/]*\\.dylib\")"
				"(subpath \"/Library\")"
				"(subpath \"/System/Library\")"
			")"
		")"
		/* "(allow file-read-data (literal \"/private/etc/hosts\"))" */
	}
};

static int num_sandbox_params = 0;
static char **sandbox_params = NULL;

void seatbelt_free_params() {
	char **param = NULL;

	if (sandbox_params == NULL)
		return;

	for (param = sandbox_params; *param; param++)
		free(*param);

	free(sandbox_params);

	/* prevent possible additional calls to pledge_add_param() from
	 * segfaulting */
	sandbox_params = NULL;
	num_sandbox_params = 0;
}

int seatbelt_add_param(const char *param, const char *value) {
	char *param_copy = NULL, *value_copy = NULL;

	/* do not add empty values - profile must handle this as optional
	 * parameter */
	if (value == NULL)
		return 0;

	param_copy = strdup(param);
	if (param_copy == NULL)
		return -1;

	/* simplistic heuristic to detect paths. Breaks if a non-path param
	 * ever starts with /. We currently only use params to provide paths.
	 * */
	if (value[0] == '/') {
		struct stat st;
		int strc = stat(value, &st);
		if (strc == -1 && errno != EACCES && errno != ENOTDIR &&
				errno !=ENOENT) {
			free(param_copy);
			return -1;
		}

		/* resolve symlinks because seatbelt gives us the real actual
		 * path to match, but only if there's a chance this works */
		if (strc == 0)
			value_copy = realpath(value, NULL);
	}

	/* just use literally if any of the above failed */
	if (value_copy == NULL)
		value_copy = strdup(value);

	if (value_copy == NULL) {
		warn("foo?");
		free(param_copy);
		return -1;
	}

	num_sandbox_params += 2;
	if ((sandbox_params = realloc(sandbox_params, (num_sandbox_params + 1)
					* sizeof(*sandbox_params))) == NULL) {
		free(value_copy);
		free(param_copy);
		return -1;
	}

	warn("adding param: %s=%s", param_copy, value_copy);
	sandbox_params[num_sandbox_params - 2] = param_copy;
	sandbox_params[num_sandbox_params - 1] = value_copy;
	sandbox_params[num_sandbox_params] = NULL;

	return 0;
}

int chngproc_intercept(int netsock, const char *root) {
	seatbelt_add_param("challenge-dir", root);

	return chngproc(netsock, root);
}

int fileproc_intercept(int certsock, const char *certdir, const char *certfile,
		const char *chainfile, const char *fullchainfile) {
	seatbelt_add_param("cert-dir", certdir);
	seatbelt_add_param("cert-file", certfile);
	seatbelt_add_param("chain-file", chainfile);
	seatbelt_add_param("full-chain-file", fullchainfile);

	return fileproc(certsock, certdir, certfile, chainfile, fullchainfile);
}

static void seatbelt_sandbox(uint64_t promises, const enum comp proccomp) {
	char *se = NULL;
	char *profile = NULL;
	size_t plen = 0;
	int i;

	/* do not sandbox twice */
	if (sandbox_check(getpid(), NULL, 0))
		return;

	/* somewhat inefficient but we do it only once */
	if ((profile = malloc(1)) == NULL)
		err(EXIT_FAILURE, "malloc sandbox profile");

	profile[0] = '\0';
	for (i = 0; i < nitems(sb_profiles); i++) {
		if ((sb_profiles[i].comp != proccomp) &&
				(sb_profiles[i].comp != COMP__MAX))
			continue;

		plen += strlen(sb_profiles[i].profile);
		if ((profile = realloc(profile, plen + 1)) == NULL)
			err(EXIT_FAILURE, "realloc sandbox profile");

		strcat(profile, sb_profiles[i].profile);
	}

	/* add the privilege separation path as parameter to allow chrooting
	 * into it and get symlinks in the path resolved. But only if we're not
	 * chrooted yet because it's unlikely to exist in the new root and also
	 * unlikely we're going to chroot() again. */
	if (seatbelt_add_param("privsep-path", PRIVSEP_PATH) == -1) {
		warn("seatbelt_add_param privsep-path");
		goto sandbox_fail;
	}

	/* they've deprecated it but all the system deamons still use it in
	 * seemingly the same way. So it might stay around for a while. */
	if (sandbox_init_with_parameters(profile, 0,
				sandbox_params, &se) != 0) {
		warn("sandbox_init_with_parameters: %s", se);
		goto sandbox_fail;
	}

	free(profile);
	seatbelt_free_params();
	return;

sandbox_fail:
	if (se)
		sandbox_free_error(se);
	if (profile)
		free(profile);
	seatbelt_free_params();
	exit(EXIT_FAILURE);
}
#endif

/* bsearch over pledgereq. return flags value if found, 0 else */
static uint64_t
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

static int
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

	/* portable chroot() and setuid(), does not return on error */
	chroot_droppriv(promises);

#if defined(HAVE_LIBSECCOMP)
	/* does not return on error */
	seccomp_sandbox(promises, proccomp);
#endif

#if defined(HAVE_LIBSANDBOX)
	/* does not return on error */
	seatbelt_sandbox(promises, proccomp);
#endif

	return 0;
}
#endif
