#ifndef STRACE_LINUX_SOCK_DIAG_H
#define STRACE_LINUX_SOCK_DIAG_H

#define SOCK_DIAG_BY_FAMILY 20

enum {
	SK_MEMINFO_RMEM_ALLOC,
	SK_MEMINFO_RCVBUF,
	SK_MEMINFO_WMEM_ALLOC,
	SK_MEMINFO_SNDBUF,
	SK_MEMINFO_FWD_ALLOC,
	SK_MEMINFO_WMEM_QUEUED,
	SK_MEMINFO_OPTMEM,
	SK_MEMINFO_BACKLOG,
	SK_MEMINFO_VARS
};

struct sock_diag_req {
	uint8_t	sdiag_family;
	uint8_t	sdiag_protocol;
};

#endif /* !STRACE_LINUX_SOCK_DIAG_H */

