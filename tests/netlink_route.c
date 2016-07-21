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
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/netlink_diag.h>
#include <linux/unix_diag.h>
#define MAX_ADDR_LEN 32
#include <linux/packet_diag.h>
#include <linux/inet_diag.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_addrlabel.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/dcbnl.h>
#include <linux/netconf.h>

#if !defined NETLINK_SOCK_DIAG && defined NETLINK_INET_DIAG
# define NETLINK_SOCK_DIAG NETLINK_INET_DIAG
#endif

static void
send_link_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.ifi_family = AF_NETLINK,
			.ifi_type = ARPHRD_LOOPBACK,
			.ifi_flags = IFF_UP,
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETLINK"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "ifi_family=AF_NETLINK, ifi_type=772" // TODO
	       ", ifi_index=0, ifi_flags=IFF_UP, ifi_change=0}}"
	       ", %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req), (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}

static void
send_addr_query(const int fd)
{
	int prefixlen = 24;
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETADDR,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.ifa_family = AF_NETLINK,
			.ifa_prefixlen = prefixlen,
			.ifa_flags = IFA_F_SECONDARY
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETADDR"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "ifa_family=AF_NETLINK, ifa_prefixlen=%d"
	       ", ifa_flags=IFA_F_SECONDARY, ifa_scope=0, ifa_index=0}}"
	       ", %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req), prefixlen, (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}

static void
send_route_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETROUTE,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.rtm_family = AF_NETLINK,
			.rtm_dst_len = 0,
			.rtm_src_len = 0,
			.rtm_tos = 0,
			.rtm_table = RT_TABLE_DEFAULT,
			.rtm_protocol = RTPROT_KERNEL,
			.rtm_scope = RT_SCOPE_UNIVERSE,
			.rtm_type = RTN_LOCAL,
			.rtm_flags = RTM_F_NOTIFY
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETROUTE"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}, {"
	       "rtm_family=AF_NETLINK, rtm_dst_len=0, rtm_src_len=0"
	       ", rtm_tos=0, rtm_table=RT_TABLE_DEFAULT, rtm_protocol=RTPROT_KERNEL"
	       ", rtm_scope=RT_SCOPE_UNIVERSE, rtm_type=RTN_LOCAL"
	       ", rtm_flags=RTM_F_NOTIFY}}, %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd,
	       (unsigned) sizeof(req), (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}

static void
send_neigh_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct ndmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETNEIGH,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.ndm_family = AF_NETLINK,
			.ndm_ifindex = 0,
			.ndm_state = NUD_PERMANENT,
			.ndm_flags = NTF_PROXY,
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETNEIGH"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {ndm_family=AF_NETLINK, ndm_ifindex=0, ndm_state=NUD_PERMANENT"
	       ", ndm_flags=NTF_PROXY, ndm_type=0}}, %u, MSG_DONTWAIT, NULL, 0)"
	       " = %u\n", fd, (unsigned) sizeof(req), (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}


static void
send_neightbl_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct ndtmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETNEIGHTBL,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.ndtm_family = AF_NETLINK,
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETNEIGHTBL"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {ndt_family=AF_NETLINK}}, %u, MSG_DONTWAIT, NULL, 0)"
	       " = %u\n", fd, (unsigned) sizeof(req), (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}

static void
send_tc_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct tcmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETQDISC,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.tcm_family = AF_NETLINK,
			.tcm_ifindex = 0,
			.tcm_handle = 0x0000ffff, /* decode this */
			.tcm_parent = 0xffff0000, /* print hexa */
			.tcm_info = 0xffff0000 /* idem */
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETQDISC"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {tcm_family=AF_NETLINK, tcm_ifindex=0, tcm_handle=%u"
	       ", tcm_parent=%u, tcm_info=%u}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(req),
	       0x0000ffff, 0xffff0000, 0xffff0000,
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}


static void
send_action_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct tcamsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETACTION,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.tca_family = AF_NETLINK,
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETACTION"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {tca_family=AF_NETLINK}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(req),
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

static void
send_addrlabel_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct ifaddrlblmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETADDRLABEL,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.ifal_family = AF_NETLINK,
			.ifal_prefixlen = 0,
			.ifal_flags = 0,
			.ifal_index = 0,
			.ifal_seq = 0
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETADDRLABEL"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {ifal_family=AF_NETLINK, ifal_prefixlen=0, ifal_flags=0"
	       ", ifal_index=0, ifal_seq=0}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(req),
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

static void
send_dcb_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct dcbmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETDCB,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.dcb_family = AF_NETLINK,
			.cmd = DCB_CMD_UNDEFINED
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETDCB"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {dcb_family=AF_NETLINK, cmd=DCB_CMD_UNDEFINED}}"
	       ", %u, MSG_DONTWAIT, NULL, 0) = %u\n", fd, (unsigned) sizeof(req),
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

static void
send_ncm_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct netconfmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETNETCONF,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.ncm_family = AF_NETLINK
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETNETCONF"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {ncm_family=AF_NETLINK}}, %u, MSG_DONTWAIT, NULL, 0) = %u\n",
	       fd, (unsigned) sizeof(req), (unsigned) sizeof(req),
	       (unsigned) sizeof(req));
}

static void
send_mdb_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct br_port_msg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETMDB,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.family = AF_NETLINK,
			.ifindex = 0
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETMDB"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {family=AF_NETLINK, ifindex=0}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(req),
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

static void
send_rtgen_query(const int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg msg;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETNSID,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.msg = {
			.rtgen_family = AF_NETLINK
		}
	};

	if (sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0) !=
	    (unsigned) sizeof(req))
		perror_msg_and_skip("sendto");

	printf("sendto(%d, {{len=%u, type=RTM_GETNSID"
	       ", flags=NLM_F_REQUEST|NLM_F_DUMP, seq=0, pid=0}"
	       ", {rtgen_family=AF_NETLINK}}, %u, MSG_DONTWAIT"
	       ", NULL, 0) = %u\n", fd, (unsigned) sizeof(req),
	       (unsigned) sizeof(req), (unsigned) sizeof(req));
}

int main(void)
{
	struct sockaddr_nl addr;
	socklen_t len = sizeof(addr);
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
		perror_msg_and_skip("socket AF_NETLINK");

	printf("socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) = %d\n", fd);
	if (bind(fd, (struct sockaddr *) &addr, len))
		perror_msg_and_skip("bind");
	printf("bind(%d, {sa_family=AF_NETLINK, nl_pid=0, "
	       "nl_groups=00000000}, %u) = 0\n", fd, len);

	send_link_query(fd);

	send_addr_query(fd);

	send_route_query(fd);

	send_neigh_query(fd);

	send_neightbl_query(fd);

	send_tc_query(fd);

	send_action_query(fd);

	send_addrlabel_query(fd);

	send_dcb_query(fd);

	send_ncm_query(fd);

	send_mdb_query(fd);

	send_rtgen_query(fd);

	printf("+++ exited with 0 +++\n");

	return 0;
}
