#ifndef STRACE_LINUX_UNIX_DIAG_H
#define STRACE_LINUX_UNIX_DIAG_H

struct unix_diag_req {
	uint8_t	 sdiag_family;
	uint8_t	 sdiag_protocol;
	uint16_t pad;
	uint32_t udiag_states;
	uint32_t udiag_ino;
	uint32_t udiag_show;
	uint32_t udiag_cookie[2];
};

#define UDIAG_SHOW_NAME		0x01
#define UDIAG_SHOW_PEER		0x04

enum {
	UNIX_DIAG_NAME,
	UNIX_DIAG_VFS,
	UNIX_DIAG_PEER,
	UNIX_DIAG_ICONS,
	UNIX_DIAG_RQLEN,
	UNIX_DIAG_MEMINFO,
	UNIX_DIAG_SHUTDOWN,
	__UNIX_DIAG_MAX,
};

struct unix_diag_msg {
	uint8_t	 udiag_family;
	uint8_t	 udiag_type;
	uint8_t	 udiag_state;
	uint8_t	 pad;
	uint32_t udiag_ino;
	uint32_t udiag_cookie[2];
};

struct unix_diag_vfs {
	uint32_t udiag_vfs_ino;
	uint32_t udiag_vfs_dev;
};

struct unix_diag_rqlen {
	uint32_t udiag_rqueue;
	uint32_t udiag_wqueue;
};

#endif /* !STRACE_LINUX_UNIX_DIAG_H */

