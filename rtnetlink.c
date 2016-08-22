/*
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

#include "defs.h"
#include "netlink.h"
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/neighbour.h>
#include <linux/dcbnl.h>
#include <linux/netconf.h>
#include <arpa/inet.h>
#include "xlat/arp_hardware_types.h"
#include "xlat/iffflags.h"
#include "xlat/ifaddrflags.h"
#include "xlat/rtm_types.h"
#include "xlat/rtm_protocol.h"
#include "xlat/rtm_scope.h"
#include "xlat/rtm_flags.h"
#include "xlat/rtm_table.h"
#include "xlat/ndm_state.h"
#include "xlat/ndm_flags.h"
#include "xlat/dcb_commands.h"
#include "xlat/rtnetlink_link_attr.h"
#include "xlat/rtnetlink_addr_attr.h"
#include "xlat/rtnetlink_route_attr.h"
#include "xlat/rtnetlink_neigh_attr.h"
#include "xlat/rtnetlink_neightbl_attr.h"
#include "xlat/rtnetlink_tc_attr.h"
#include "xlat/rtnetlink_action_attr.h"
#include "xlat/rtnetlink_addrlabel_attr.h"
#include "xlat/rtnetlink_dcb_attr.h"
#include "xlat/rtnetlink_nc_attr.h"
#include "xlat/rtnetlink_mdb_attr.h"
#include "xlat/rtnetlink_nsid_attr.h"

static bool
decode_address(int af, int len, const void *addr)
{
	int buflen = 80;
	char buf[buflen];

	switch (af) {
	case AF_INET:
	case AF_INET6:
		inet_ntop(af, addr, buf, buflen);
		break;
	default:
		return false;
	}

	tprintf("\"%s\"", buf);
	return true;
}

#define MAX_PHYS_ITEM_ID_LEN 32

static const struct nla_policy ifla_policy[] = {
	[IFLA_IFNAME]		= { .type = NLA_STRING, .len = IFNAMSIZ-1 },
	[IFLA_ADDRESS]		= { .type = NLA_BINARY, .len = MAX_ADDR_LEN },
	[IFLA_BROADCAST]	= { .type = NLA_BINARY, .len = MAX_ADDR_LEN },
	[IFLA_MTU]		= { .type = NLA_U32 },
	[IFLA_LINK]		= { .type = NLA_U32 },
	[IFLA_MASTER]		= { .type = NLA_U32 },
	[IFLA_CARRIER]		= { .type = NLA_U8 },
	[IFLA_TXQLEN]		= { .type = NLA_U32 },
	[IFLA_WEIGHT]		= { .type = NLA_U32 },
	[IFLA_OPERSTATE]	= { .type = NLA_U8 },
	[IFLA_LINKMODE]		= { .type = NLA_U8 },
	[IFLA_NET_NS_PID]	= { .type = NLA_U32 },
	[IFLA_NET_NS_FD]	= { .type = NLA_U32 },
	[IFLA_IFALIAS]	        = { .type = NLA_STRING, .len = IFALIASZ-1 },
	[IFLA_EXT_MASK]		= { .type = NLA_U32 },
	[IFLA_PROMISCUITY]	= { .type = NLA_U32 },
	[IFLA_NUM_TX_QUEUES]	= { .type = NLA_U32 },
	[IFLA_NUM_RX_QUEUES]	= { .type = NLA_U32 },
	[IFLA_PHYS_PORT_ID]	= { .type = NLA_BINARY, .len = MAX_PHYS_ITEM_ID_LEN },
	[IFLA_CARRIER_CHANGES]	= { .type = NLA_U32 },  /* ignored */
	[IFLA_PHYS_SWITCH_ID]	= { .type = NLA_BINARY, .len = MAX_PHYS_ITEM_ID_LEN },
	[IFLA_LINK_NETNSID]	= { .type = NLA_S32 },
	[IFLA_PROTO_DOWN]	= { .type = NLA_U8 },
};

static void
decode_rtnetlink_link(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct ifinfomsg ifinfo;

	if (*len < sizeof(ifinfo)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &ifinfo) == -1)
		return;

	*len -= sizeof(ifinfo);
	*addr += sizeof(ifinfo);

	tprints(", {ifi_family=");
	printxval(addrfams, ifinfo.ifi_family, "AF_???");
	tprints(", ifi_type=");
	printxval(arp_hardware_types, ifinfo.ifi_type, "ARPHRD_???");
	tprintf(", ifi_index=%d", ifinfo.ifi_index);
	tprints(", ifi_flags=");

	printflags(iffflags, ifinfo.ifi_flags, "IFF_???");

	tprintf(", ifi_change=%u}", ifinfo.ifi_change);
}

static const struct nla_policy ifa_policy[] = {
	[IFA_LOCAL] = {.type = NLA_UNSPEC}, /* NLA_ADDRESS */
	[IFA_ADDRESS] = {.type = NLA_UNSPEC}, /* NLA_ADDRESS */
	[IFA_BROADCAST] = {.type = NLA_UNSPEC}, /* NLA_ADDRESS */
	[IFA_LABEL] = {.type = NLA_STRING},
	[IFA_FLAGS] = {.type = NLA_U32}
};

static bool
decode_addr_attrs(struct tcb *tcp, unsigned long addr, unsigned long len,
		  int nla_type, unsigned family)
{
	switch (nla_type)
	{
	case IFA_LOCAL:
	case IFA_ADDRESS:
	case IFA_BROADCAST:{
		uint8_t buf[len];
		if (umoven(tcp, addr, len, buf))
			return false;
		return decode_address(family, len, buf);
		break;
	}
	default:
		return false;
	}
}

static unsigned
decode_rtnetlink_addr(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct ifaddrmsg ifaddr;

	if (*len < sizeof(ifaddr)) {
		printstr(tcp, *addr, *len);
		return AF_UNSPEC;
	}
	if (umove_or_printaddr(tcp, *addr, &ifaddr) == -1)
		return AF_UNSPEC;

	*len -= sizeof(ifaddr);
	*addr += sizeof(ifaddr);

	tprints(", {ifa_family=");
	printxval(addrfams, ifaddr.ifa_family, "AF_???");
	tprintf(", ifa_prefixlen=%u", ifaddr.ifa_prefixlen);

	tprints(", ifa_flags=");
	printflags(ifaddrflags, ifaddr.ifa_flags, "IFA_F_???");

	tprintf(", ifa_scope=%u, ifa_index=%d}", ifaddr.ifa_scope,
		ifaddr.ifa_index);

	return ifaddr.ifa_family;
}

static const struct nla_policy rtm_policy[] = {
	[RTA_IIF] = {.type = NLA_U32},
	[RTA_OIF] = {.type = NLA_U32},
	[RTA_PRIORITY] = {.type = NLA_U32},
	[RTA_FLOW] = {.type = NLA_U32},
	[RTA_ENCAP_TYPE] = {.type = NLA_U16},
};

static void
decode_rtnetlink_rtmsg(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct rtmsg rtmsg;

	if (*len < sizeof(rtmsg)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &rtmsg) == -1)
		return;

	*len -= sizeof(rtmsg);
	*addr += sizeof(rtmsg);

	tprints(", {rtm_family=");
	printxval(addrfams, rtmsg.rtm_family, "AF_???");
	tprintf(", rtm_dst_len=%u, rtm_src_len=%u, rtm_tos=%u, ",
		rtmsg.rtm_dst_len, rtmsg.rtm_src_len, rtmsg.rtm_tos);

	tprints("rtm_table=");
	printxval(rtm_table, rtmsg.rtm_table, "RT_TABLE_???");
	tprints(", rtm_protocol=");
	printxval(rtm_protocol, rtmsg.rtm_protocol, "RTPROT_???");
	tprints(", rtm_scope=");
	printxval(rtm_scope, rtmsg.rtm_scope, "RT_SCOPE_???");
	tprints(", rtm_type=");
	printxval(rtm_types, rtmsg.rtm_type, "RTN_???");

	tprints(", rtm_flags=");
	printflags(rtm_flags, rtmsg.rtm_flags, "RTM_F_???");

	tprints("}");
}

static const struct nla_policy rtnl_net_policy[] = {
	[NETNSA_NSID] = {.type = NLA_S32},
	[NETNSA_PID] = {.type = NLA_U32},
	[NETNSA_FD] = {.type = NLA_U32}
};

static void
decode_rtnetlink_rtgenmsg(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct rtgenmsg rtgenmsg;

	if (*len < sizeof(rtgenmsg)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &rtgenmsg) == -1)
		return;

	*len -= sizeof(rtgenmsg);
	*addr += sizeof(rtgenmsg);

	tprints(", {rtgen_family=");
	printxval(addrfams, rtgenmsg.rtgen_family, "AF_???");
	tprints("}");
}

static const struct nla_policy neigh_policy[] = {
	[NDA_PROBES] = {.type = NLA_U32},
	[NDA_IFINDEX] = {.type = NLA_U32},
	[NDA_MASTER] = {.type = NLA_U32},
};

static void
decode_rtnetlink_neigh(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct ndmsg ndmsg;

	if (*len < sizeof(ndmsg)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &ndmsg) == -1)
		return;

	*len -= sizeof(ndmsg);
	*addr += sizeof(ndmsg);

	tprints(", {ndm_family=");
	printxval(addrfams, ndmsg.ndm_family, "AF_???");
	tprintf(", ndm_ifindex=%d", ndmsg.ndm_ifindex);
	tprints(", ndm_state=");
	printxval(ndm_state, ndmsg.ndm_state, "NUD_???");
	tprints(", ndm_flags=");
	printflags(ndm_flags, ndmsg.ndm_flags, "NTF_???");
	tprintf(", ndm_type=%u", ndmsg.ndm_type);

	tprints("}");
}

static const struct nla_policy nl_neightbl_policy[] = {
	[NDTA_NAME] = {.type = NLA_STRING},
	[NDTA_THRESH1] = {.type = NLA_U32},
	[NDTA_THRESH2] = {.type = NLA_U32},
	[NDTA_THRESH3] = {.type = NLA_U32},
	[NDTA_GC_INTERVAL] = {.type = NLA_U64},
};

static void
decode_rtnetlink_neightbl(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct ndtmsg ndtmsg;

	if (*len < sizeof(ndtmsg)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &ndtmsg) == -1)
		return;

	*len -= sizeof(ndtmsg);
	*addr += sizeof(ndtmsg);

	tprints(", {ndt_family=");
	printxval(addrfams, ndtmsg.ndtm_family, "AF_???");

	tprints("}");
}

static const struct nla_policy tc_policy[] = {
	[TCA_KIND] = {.type = NLA_STRING},
	[TCA_FCNT] = {.type = NLA_U32},
};

static void
decode_rtnetlink_tc(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct tcmsg tcmsg;

	if (*len < sizeof(tcmsg)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &tcmsg) == -1)
		return;

	*len -= sizeof(tcmsg);
	*addr += sizeof(tcmsg);

	tprints(", {tcm_family=");
	printxval(addrfams, tcmsg.tcm_family, "AF_???");
	tprintf(", tcm_ifindex=%d", tcmsg.tcm_ifindex);
	tprintf(", tcm_handle=%u", tcmsg.tcm_handle);
	tprintf(", tcm_parent=%u", tcmsg.tcm_parent);
	tprintf(", tcm_info=%u", tcmsg.tcm_info);

	tprints("}");
}

static const struct nla_policy nl_action_policy[] = {
	[TCA_ACT_KIND] = {.type = NLA_STRING},
	[TCA_ACT_INDEX] = {.type = NLA_U32}
};

static void
decode_rtnetlink_action(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct tcamsg tca;

	if (*len < sizeof(tca)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &tca) == -1)
		return;

	*len -= sizeof(tca);
	*addr += sizeof(tca);

	tprints(", {tca_family=");
	printxval(addrfams, tca.tca_family, "AF_???");
	tprints("}");
}

static const struct nla_policy addrlabel_policy[] = {
	[IFAL_LABEL] = {.type = NLA_U32},
};

static void
decode_rtnetlink_addrlbl(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct ifaddrlblmsg ifal;

	if (*len < sizeof(ifal)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &ifal) == -1)
		return;

	*len -= sizeof(ifal);
	*addr += sizeof(ifal);

	tprints(", {ifal_family=");
	printxval(addrfams, ifal.ifal_family, "AF_???");
	tprintf(", ifal_prefixlen=%u, ifal_flags=%u, ifal_index=%u"
		", ifal_seq=%u}", ifal.ifal_prefixlen, ifal.ifal_flags,
		ifal.ifal_index, ifal.ifal_seq);
}

static const struct nla_policy dcbnl_policy[] = {
	[DCB_ATTR_IFNAME] = {.type = NLA_NUL_STRING, .len = IFNAMSIZ - 1},
	[DCB_ATTR_STATE] = {.type = NLA_U8},
	[DCB_ATTR_SET_ALL] = {.type = NLA_U8},
	[DCB_ATTR_PERM_HWADDR] = {.type = NLA_FLAG},
	[DCB_ATTR_PFC_STATE] = {.type = NLA_U8},
	[DCB_ATTR_DCBX] = {.type = NLA_U8}
};

static void
decode_rtnetlink_dcb(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct dcbmsg dcb;

	if (*len < sizeof(dcb)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &dcb) == -1)
		return;

	*len -= sizeof(dcb);
	*addr += sizeof(dcb);

	tprints(", {dcb_family=");
	printxval(addrfams, dcb.dcb_family, "AF_???");
	tprints(", cmd=");
	printxval(dcb_commands, dcb.cmd, "DCB_CMD_???");

	tprints("}");
}

static const struct nla_policy ncm_policy[] = {
	[NETCONFA_IFINDEX] = {.type = NLA_S32},
	[NETCONFA_FORWARDING] = {.type = NLA_S32},
	[NETCONFA_RP_FILTER] = {.type = NLA_S32},
	[NETCONFA_MC_FORWARDING] = {.type = NLA_S32},
	[NETCONFA_PROXY_NEIGH] = {.type = NLA_S32},
	[NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN] = {.type = NLA_S32}
};

static void
decode_rtnetlink_ncm(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct netconfmsg ncm;

	if (*len < sizeof(ncm)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &ncm) == -1)
		return;

	*len -= sizeof(ncm);
	*addr += sizeof(ncm);

	tprints(", {ncm_family=");
	printxval(addrfams, ncm.ncm_family, "AF_???");
	tprints("}");
}

static void
decode_rtnetlink_mdb(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct br_port_msg bpm;

	if (*len < sizeof(bpm)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &bpm) == -1)
		return;

	*len -= sizeof(bpm);
	*addr += sizeof(bpm);

	tprints(", {family=");
	printxval(addrfams, bpm.family, "AF_???");
	tprintf(", ifindex=%u", bpm.ifindex);
	tprints("}");
}

void
decode_rtnetlink(struct tcb *tcp, unsigned long addr, unsigned long len,
		 unsigned int type)
{
	unsigned family;
	switch (type)
	{
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_GETLINK:
	case RTM_SETLINK:
		decode_rtnetlink_link(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_link_attr,
				    ifla_policy, NULL, "IFLA_???");
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_GETADDR:
	case RTM_GETMULTICAST:
	case RTM_GETANYCAST:
		family = decode_rtnetlink_addr(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, family, rtnetlink_addr_attr,
				    ifa_policy, decode_addr_attrs, "IFA_???");
		break;
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
	case RTM_GETROUTE:
	case RTM_NEWRULE:
	case RTM_DELRULE:
	case RTM_GETRULE:
		decode_rtnetlink_rtmsg(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_route_attr,
				    rtm_policy, NULL, "RTA_???");
		break;
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
	case RTM_GETNEIGH:
		decode_rtnetlink_neigh(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_neigh_attr,
				    neigh_policy, NULL, "NDA_???");
		break;
	case RTM_NEWNEIGHTBL:
	case RTM_GETNEIGHTBL:
	case RTM_SETNEIGHTBL:
		decode_rtnetlink_neightbl(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_neightbl_attr,
				    nl_neightbl_policy, NULL, "NDTA_???");
		break;
	case RTM_NEWQDISC:
	case RTM_DELQDISC:
	case RTM_GETQDISC:
	case RTM_NEWTCLASS:
	case RTM_DELTCLASS:
	case RTM_GETTCLASS:
	case RTM_NEWTFILTER:
	case RTM_DELTFILTER:
	case RTM_GETTFILTER:
		decode_rtnetlink_tc(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_tc_attr,
				    tc_policy, NULL, "TCA_???");
		break;
	case RTM_NEWACTION:
	case RTM_DELACTION:
	case RTM_GETACTION:
		decode_rtnetlink_action(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_action_attr,
				    nl_action_policy, NULL, "TCA_ACT_???");
		break;
	case RTM_NEWADDRLABEL:
	case RTM_DELADDRLABEL:
	case RTM_GETADDRLABEL:
		decode_rtnetlink_addrlbl(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_addrlabel_attr,
				    addrlabel_policy, NULL, "IFAL_???");
		break;
	case RTM_GETDCB:
	case RTM_SETDCB:
		decode_rtnetlink_dcb(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_dcb_attr,
				    dcbnl_policy, NULL, "DCB_ATTR_???");
		break;
	case RTM_GETNETCONF:
	case RTM_NEWNETCONF:
		decode_rtnetlink_ncm(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_nc_attr,
				    ncm_policy, NULL, "NETCONFA_???");
		break;
	case RTM_NEWMDB:
	case RTM_DELMDB:
	case RTM_GETMDB:
		decode_rtnetlink_mdb(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_mdb_attr, NULL,
				    NULL, "MDBA_???");
		break;
	case RTM_NEWNSID:
	case RTM_DELNSID:
	case RTM_GETNSID:
		decode_rtnetlink_rtgenmsg(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, AF_UNSPEC, rtnetlink_nsid_attr,
				    rtnl_net_policy, NULL, "NETNSA_???");
		break;
	}

	if (NETLINK_ALIGN_INF(len)) {
		tprints(", ");
		printstr(tcp, addr, len);
	}
}
