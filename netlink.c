/*
 * Copyright (c) 2016 Fabien Siron <fabien.siron@epita.fr>
 * Copyright (c) 2016 Dmitry V. Levin <ldv@altlinux.org>
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

#include "defs.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/selinux_netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include "xlat/netlink_flags.h"
#include "xlat/netlink_get_flags.h"
#include "xlat/netlink_new_flags.h"
#include "xlat/netlink_types.h"
#include "xlat/netlink_protocols.h"
#include "xlat/netlink_route_types.h"
#include "xlat/netlink_sock_diag_types.h"
#include "xlat/netlink_xfrm_types.h"
#include "xlat/netlink_selinux_types.h"
#include "xlat/netlink_audit_types.h"
#include "xlat/netlink_netfilter_ids.h"
#include "netlink.h"

static bool
fetch_nlattr(struct tcb *tcp, struct nlattr *nlattr,
	     const unsigned long addr, const unsigned long len)
{
	if (len < sizeof(struct nlattr)) {
		printstr(tcp, addr, len);
		return false;
	}

	if (umove_or_printaddr(tcp, addr, nlattr))
		return false;

	return true;
}

static void
decode_nlattr_data(struct tcb *tcp, unsigned long addr, unsigned long len,
		   unsigned nla_type, const struct nla_policy policy[])
{
	if (!policy) {
		printstr(tcp, addr, len);
		return;
	}

	switch (policy[nla_type].type) {
	case NLA_STRING: case NLA_NUL_STRING:
		if (policy[nla_type].len == 0 || len < policy[nla_type].len)
			printstr(tcp, addr, len - 1);
		else
			printstr(tcp, addr, len);
		break;
	case NLA_U64: {
		uint64_t n;
		if (len >= 8 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%lu", n);
		break;
	}
	case NLA_U32: {
		uint32_t n;
		if (len >= 4 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%u", n);
		break;
	}
	case NLA_U16: {
		uint16_t n;
		if (len >= 2 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%u", n);
		break;
	}
	case NLA_U8: {
		uint8_t n;
		if (len >= 1 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%u", n);
		break;
	}
	case NLA_S64: {
		int64_t n;
		if (len >= 8 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%ld", n);
		break;
	}
	case NLA_S32: {
		int32_t n;
		if (len >= 4 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%d", n);
		break;
	}
	case NLA_S16: {
		int16_t n;
		if (len >= 2 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%d", n);
		break;
	}
	case NLA_S8: {
		int8_t n;
		if (len >= 1 && umove(tcp, addr, &n))
			printstr(tcp, addr, len);
		else
			tprintf("%d", n);
		break;
	}
	default:
		printstr(tcp, addr, len);
	}
}

unsigned long
decode_nlattr(struct tcb *tcp, unsigned long addr, unsigned long len,
	      const struct xlat *table, const struct nla_policy policy[],
	      const char *dftl)
{
	struct nlattr nlattr;

	if (len < sizeof(nlattr))
		return len;

	len -= NETLINK_ALIGN_UP(addr) - addr;
	addr = NETLINK_ALIGN_UP(addr);

	while (fetch_nlattr(tcp, &nlattr, addr, len)) {
		unsigned long nlattr_len = NLA_ALIGN(nlattr.nla_len);
		unsigned long next_addr = 0, next_len = 0;

		if (nlattr.nla_len >= sizeof(struct nlattr)) {
			next_len = (len >= nlattr_len) ? len - nlattr_len : 0;

			if (next_len && addr + nlattr_len > addr)
				next_addr = addr + nlattr_len;
		}

		/* decode one nlattr*/
		tprintf(", {{nla_len=%u, nla_type=", nlattr.nla_len);

		printxval(table, nlattr.nla_type, dftl);

		tprints("}, ");

		decode_nlattr_data(tcp, addr + sizeof(struct nlattr),
				   nlattr.nla_len - sizeof(struct nlattr),
				   nlattr.nla_type,
				   policy);

		tprints("}");

		if (!next_addr)
			return next_len;

		addr = next_addr;
		len = next_len;
	}

	return len;
}

/*
 * Fetch a struct nlmsghdr from the given address.
 */
static bool
fetch_nlmsghdr(struct tcb *tcp, struct nlmsghdr *nlmsghdr,
	       const unsigned long addr, const unsigned long len)
{
	if (len < sizeof(struct nlmsghdr)) {
		printstr(tcp, addr, len);
		return false;
	}

	if (umove_or_printaddr(tcp, addr, nlmsghdr))
		return false;

	return true;
}

static unsigned long
nlmsg_data(unsigned long nlh) {
	return nlh + NLMSG_LENGTH(0);
}

static void
decode_netlink_type(int type, int proto) {
	if (type < NLMSG_MIN_TYPE) {
		printxval(netlink_types, type, "NLMSG_???");
		return;
	}

	switch (proto) {
	case NETLINK_ROUTE:
		printxval(netlink_route_types, type, "RTM_???");
		break;
	case NETLINK_SOCK_DIAG:
		printxval(netlink_sock_diag_types, type, "SOCK_DIAG_???");
		break;
	case NETLINK_XFRM:
		printxval(netlink_xfrm_types, type, "XFRM_MSG_???");
		break;
	case NETLINK_AUDIT:
		printxval(netlink_audit_types, type, "AUDIT_???");
		break;
	case NETLINK_SELINUX:
		printxval(netlink_selinux_types, type, "SELNL_???");
		break;
	case NETLINK_NETFILTER:
		tprints("{");
		printxval(netlink_netfilter_ids, NFNL_SUBSYS_ID(type),
			  "NFNL_SUBSYS_???");
		tprintf(", %d}", NFNL_MSG_TYPE(type));
		break;
	default:
		tprints("???");
	}
}

static void
decode_netlink_flags(int type, int proto, unsigned flags)
{
	const char *type_s = NULL;
	if (type < NLMSG_MIN_TYPE) {
		printflags(netlink_flags, flags, "NLM_F_???");
		return;
	}

	if (proto == NETLINK_ROUTE)
		type_s = xlookup(netlink_route_types, type);
	else if (proto == NETLINK_XFRM)
		type_s = xlookup(netlink_xfrm_types, type);
	else if (proto == NETLINK_SOCK_DIAG) {
		printflags(netlink_get_flags, flags, "NLM_F_???");
		return;
	}

	if (type_s != NULL) {
		if (strstr(type_s, "GET")) {
			printflags(netlink_get_flags, flags, "NLM_F_???");
			return;
		} else if (strstr(type_s, "NEW")) {
			printflags(netlink_new_flags, flags, "NLM_F_???");
			return;
		}
	}

	printflags(netlink_flags, flags, "NLM_F_???");
}

static void
print_nlmsghdr(struct tcb *tcp, const struct nlmsghdr *const nlmsghdr, int proto)
{
	/* print the whole structure regardless of its nlmsg_len */

	tprintf("{len=%u, type=", nlmsghdr->nlmsg_len);

	decode_netlink_type(nlmsghdr->nlmsg_type, proto);

	tprints(", flags=");
	decode_netlink_flags(nlmsghdr->nlmsg_type, proto, nlmsghdr->nlmsg_flags);

	tprintf(", seq=%u, pid=%u}", nlmsghdr->nlmsg_seq,
		nlmsghdr->nlmsg_pid);
}

static void
decode_netlink_error(struct tcb *tcp, unsigned long addr, unsigned long size,
		     int proto)
{
	struct nlmsgerr err;

	if (umove_or_printaddr(tcp, addr, &err) < 0)
		return;

	tprintf(", {error=\"%s\", msg=", strerror(-err.error));

	print_nlmsghdr(tcp, &err.msg, proto);
}

static int
decode_nlmsghdr_with_payload(struct tcb *tcp, int fd,
			     const struct nlmsghdr *const nlmsghdr,
			     const unsigned long addr,
			     const unsigned long len)
{
	int proto;

	tprints("{");
	proto = getfdnlproto(tcp, fd, netlink_protocols);
	print_nlmsghdr(tcp, nlmsghdr, proto);

	unsigned long nlmsg_len =
		nlmsghdr->nlmsg_len > len ? len : nlmsghdr->nlmsg_len;
	if (nlmsg_len > sizeof(struct nlmsghdr)) {
		unsigned long data = nlmsg_data(addr);

		if (nlmsghdr->nlmsg_type < NLMSG_MIN_TYPE) {
			switch (nlmsghdr->nlmsg_type)
			{
			case NLMSG_ERROR:
				decode_netlink_error(tcp, data,
						     nlmsghdr->nlmsg_len -
						     sizeof(nlmsghdr),
						     proto);
			case NLMSG_DONE:
				tprints("}");
				return 0;
			default:
				tprints(", ");

				printstr(tcp, addr + sizeof(struct nlmsghdr),
					 nlmsg_len - sizeof(struct nlmsghdr));
				tprints("}");
				return 1;
			}
		}

		switch (proto)
		{
		case NETLINK_SOCK_DIAG:
			decode_netlink_sock_diag(tcp, data,
						 nlmsghdr->nlmsg_len -
						 sizeof(struct nlmsghdr),
						 nlmsghdr->nlmsg_type,
						 nlmsghdr->nlmsg_flags &
						 NLM_F_REQUEST);
			break;
		case NETLINK_ROUTE:
			decode_rtnetlink(tcp, data, nlmsghdr->nlmsg_len -
					 sizeof(struct nlmsghdr),
					 nlmsghdr->nlmsg_type);
			break;
		default:
			tprints(", ");

			printstr(tcp, addr + sizeof(struct nlmsghdr),
				 nlmsg_len - sizeof(struct nlmsghdr));
		}
	}

	tprints("}");

	return 1;
}

void
decode_netlink(struct tcb *tcp, int fd, unsigned long addr, unsigned long len)
{
	struct nlmsghdr nlmsghdr;
	bool print_array = false;
	unsigned int elt;

	for (elt = 0; fetch_nlmsghdr(tcp, &nlmsghdr, addr, len); elt++) {
		if (abbrev(tcp) && elt == max_strlen) {
			tprints("...");
			break;
		}

		unsigned long nlmsg_len = NLMSG_ALIGN(nlmsghdr.nlmsg_len);
		unsigned long next_addr = 0, next_len = 0;

		if (nlmsghdr.nlmsg_len >= sizeof(struct nlmsghdr)) {
			next_len = (len >= nlmsg_len) ? len - nlmsg_len : 0;

			if (next_len && addr + nlmsg_len > addr)
				next_addr = addr + nlmsg_len;
		}

		if (!print_array && next_addr) {
			tprints("[");
			print_array = true;
		}

		if (!decode_nlmsghdr_with_payload(tcp, fd, &nlmsghdr, addr, len))
			break;

		if (!next_addr)
			break;

		tprints(", ");
		addr = next_addr;
		len = next_len;
	}

	if (print_array) {
		tprints("]");
	}
}
