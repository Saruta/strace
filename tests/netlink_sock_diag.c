/*
 * Copyright (c) 2014-2016 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2016 Fabien Siron <fabien.siron@epita.fr>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tests.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/netlink_diag.h>
#include <linux/unix_diag.h>
#define MAX_ADDR_LEN 32
#include <linux/packet_diag.h>
#include <linux/inet_diag.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#if !defined NETLINK_SOCK_DIAG && defined NETLINK_INET_DIAG
# define NETLINK_SOCK_DIAG NETLINK_INET_DIAG
#endif

static void
send_netlink_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct netlink_diag_req ndr;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.ndr = {
			.sdiag_family = AF_NETLINK,
			.sdiag_protocol = NDIAG_PROTO_ALL,
			.ndiag_show = NDIAG_SHOW_MEMINFO
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "sdiag_family=AF_NETLINK, sdiag_protocol=NDIAG_PROTO_ALL"
	       ", ndiag_ino=0, ndiag_show=NDIAG_SHOW_MEMINFO, ndiag_cookie="
	       "{0, 0}}}, %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req), (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}

static void
send_netlink_msg(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct netlink_diag_msg ndm;
		struct nlattr nla;
		char magic[4];
	} msg = {
		.nlh = {
			.nlmsg_len = sizeof(msg),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP
		},
		.ndm = {
			.ndiag_family = AF_NETLINK,
			.ndiag_protocol = NETLINK_ROUTE,
		},
		.nla = {
			.nla_len = sizeof(msg.magic) + sizeof(msg.nla),
			.nla_type = NETLINK_DIAG_GROUPS
		},
		.magic = "abcd"
	};

	if (sendto(fd, &msg, sizeof(msg), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(msg))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY"
	       ", flags=NLM_F_DUMP, seq=0, pid=0}, {ndiag_family=AF_NETLINK"
	       ", ndiag_type=0, ndiag_protocol=NETLINK_ROUTE, ndiag_state=0"
	       ", ndiag_portid=0, ndiag_dst_portid=0, ndiag_dst_group=0"
	       ", ndiag_ino=0, ndiag_cookie={0, 0}}, {{nla_len=%u"
	       ", nla_type=NETLINK_DIAG_GROUPS}, \"abcd\"}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(msg),
	       (unsigned) (sizeof(msg.magic) + sizeof(msg.nla)),
	       (unsigned) sizeof(msg), (unsigned) sizeof(msg));
}

static void
send_unix_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct unix_diag_req udr;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.udr = {
			.sdiag_family = AF_UNIX,
			.udiag_states = -1,
			.udiag_show = UDIAG_SHOW_NAME
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "sdiag_family=AF_UNIX, sdiag_protocol=0"
	       ", udiag_states=%u, udiag_ino=0, udiag_show=UDIAG_SHOW_NAME"
	       ", udiag_cookie={0, 0}}}, %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req), (unsigned)-1,
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

static void
send_unix_msg(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct unix_diag_msg udm;
		struct nlattr nla;
		char magic[4];
	} msg = {
		.nlh = {
			.nlmsg_len = sizeof(msg),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP
		},
		.udm = {
			.udiag_family = AF_UNIX,
		},
		.nla = {
			.nla_len = sizeof(msg.magic) + sizeof(msg.nla),
			.nla_type = UNIX_DIAG_NAME
		},
		.magic = "abcd"
	};

	if (sendto(fd, &msg, sizeof(msg), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(msg))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY"
	       ", flags=NLM_F_DUMP, seq=0, pid=0}, {"
	       "udiag_family=AF_UNIX, udiag_type=0, udiag_state=0"
	       ", udiag_ino=0, udiag_cookie={0, 0}}, {{nla_len=%u"
	       ", nla_type=UNIX_DIAG_NAME}, \"abcd\"}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(msg),
	       (unsigned) (sizeof(msg.magic) + sizeof(msg.nla)),
	       (unsigned) sizeof(msg), (unsigned) sizeof(msg));
}

static void
send_inet_query(const int fd)
{
	const char address[] = "8.8.8.8";
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 idr;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.idr = {
			.sdiag_family = AF_INET,
			.sdiag_protocol = IPPROTO_TCP,
			.idiag_states = -1
		}
	};

	if (!inet_pton(AF_INET, address, &req.idr.id.idiag_src))
		perror_msg_and_skip("sendto");
	if (!inet_pton(AF_INET, address, &req.idr.id.idiag_dst))
		perror_msg_and_skip("sendto");


	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "sdiag_family=AF_INET, sdiag_protocol=IPPROTO_TCP"
	       ", idiag_ext=0, idiag_states=%u, id={idiag_sport=0, idiag_dport=0"
	       ", idiag_src=%s, idiag_dst=%s, idiag_if=0, idiag_cookie={0, 0}}}}"
	       ", %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req), (unsigned)-1, address, address,
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

static void
send_inet_query_compat(const int fd)
{
	const char address[] = "8.8.8.8";
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req idr;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = TCPDIAG_GETSOCK,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.idr = {
			.idiag_family = AF_INET,
		}
	};

	if (!inet_pton(AF_INET, address, &req.idr.id.idiag_src))
		perror_msg_and_skip("sendto");
	if (!inet_pton(AF_INET, address, &req.idr.id.idiag_dst))
		perror_msg_and_skip("sendto");

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
		(unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=TCPDIAG_GETSOCK"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "idiag_family=AF_INET, idiag_src_len=0, idiag_dst_len=0"
	       ", idiag_ext=0, id={idiag_sport=0, idiag_dport=0, idiag_src=%s"
	       ", idiag_dst=%s, idiag_if=0, idiag_cookie={0, 0}}, idiag_states=0"
	       ", idiag_dbs=0}}, %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req), address, address, (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}

static void
send_inet_msg(const int fd)
{
	const char address[] = "8.8.8.8";
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_msg idm;
		struct nlattr nla;
		char magic[4];
	} msg = {
		.nlh = {
			.nlmsg_len = sizeof(msg),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP
		},
		.idm = {
			.idiag_family = AF_INET,
		},
		.nla = {
			.nla_len = sizeof(msg.magic) + sizeof(msg.nla),
			.nla_type = INET_DIAG_MEMINFO
		},
		.magic = "abcd"
	};

	if (!inet_pton(AF_INET, address, &msg.idm.id.idiag_src))
		perror_msg_and_skip("sendto");
	if (!inet_pton(AF_INET, address, &msg.idm.id.idiag_dst))
		perror_msg_and_skip("sendto");

	if (sendto(fd, &msg, sizeof(msg), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(msg))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY"
	       ", flags=NLM_F_DUMP, seq=0, pid=0}, {idiag_family=AF_INET"
	       ", idiag_state=0, idiag_timer=0, idiag_retrans=0, id={idiag_sport=0"
	       ", idiag_dport=0, idiag_src=%s, idiag_dst=%s, idiag_if=0"
	       ", idiag_cookie={0, 0}}, idiag_expires=0, idiag_rqueue=0"
	       ", idiag_wqueue=0, idiag_uid=0, idiag_inode=0}, {{nla_len=%u"
	       ", nla_type=INET_DIAG_MEMINFO}, \"abcd\"}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(msg), address, address,
	       (unsigned) (sizeof(msg.magic) + sizeof(msg.nla)),
	       (unsigned) sizeof(msg), (unsigned) sizeof(msg));
}

static void
send_packet_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct packet_diag_req udr;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.udr = {
			.sdiag_family = AF_PACKET,
			.sdiag_protocol = ETH_P_LOOP,
			.pdiag_show = PACKET_SHOW_INFO
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "sdiag_family=AF_PACKET, sdiag_protocol=ETH_P_LOOP, pdiag_ino=0"
	       ", pdiag_show=PACKET_SHOW_INFO, pdiag_cookie={0, 0}}}"
	       ", %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req),
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

static void
send_packet_msg(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct packet_diag_msg udm;
		struct nlattr nla;
		char magic[4];
	} msg = {
		.nlh = {
			.nlmsg_len = sizeof(msg),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_DUMP
		},
		.udm = {
			.pdiag_family = AF_PACKET,
		},
		.nla = {
			.nla_len = sizeof(msg.magic) + sizeof(msg.nla),
			.nla_type = PACKET_DIAG_UID
		},
		.magic = "abcd"
	};

	if (sendto(fd, &msg, sizeof(msg), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(msg))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=SOCK_DIAG_BY_FAMILY, flags=NLM_F_DUMP"
	       ", seq=0, pid=0}, {pdiag_family=AF_PACKET, pdiag_type=0"
	       ", pdiag_num=0, pdiag_ino=0, pdiag_cookie={0, 0}}, {{nla_len=%u"
	       ", nla_type=PACKET_DIAG_UID}, \"abcd\"}}, %u"
	       ", MSG_DONTWAIT, NULL, 0) = %u\n", fd, (unsigned) sizeof(msg),
	       (unsigned) (sizeof(msg.magic) + sizeof(msg.nla)),
	       (unsigned) sizeof(msg), (unsigned) sizeof(msg));
}

int main(void)
{
	struct sockaddr_nl addr;
	socklen_t len = sizeof(addr);
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)) == -1)
		perror_msg_and_skip("socket AF_NETLINK");

	printf("socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG) = %d\n",
	       fd);
	if (bind(fd, (struct sockaddr *) &addr, len))
		perror_msg_and_skip("bind");
	printf("bind(%d, {sa_family=AF_NETLINK, nl_pid=0, "
	       "nl_groups=00000000}, %u) = 0\n", fd, len);

	send_netlink_query(fd);
	send_netlink_msg(fd);
	send_unix_query(fd);
	send_unix_msg(fd);
	send_inet_query_compat(fd);
	send_inet_query(fd);
	send_inet_msg(fd);
	send_packet_query(fd);
	send_packet_msg(fd);

	printf("+++ exited with 0 +++\n");

	return 0;
}
