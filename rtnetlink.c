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

static void
decode_rtnetlink_addr(struct tcb *tcp, unsigned long *addr, unsigned long *len)
{
	struct ifaddrmsg ifaddr;

	if (*len < sizeof(ifaddr)) {
		printstr(tcp, *addr, *len);
		return;
	}
	if (umove_or_printaddr(tcp, *addr, &ifaddr) == -1)
		return;

	*len -= sizeof(ifaddr);
	*addr += sizeof(ifaddr);

	tprints(", {ifa_family=");
	printxval(addrfams, ifaddr.ifa_family, "AF_???");
	tprintf(", ifa_prefixlen=%u", ifaddr.ifa_prefixlen);

	tprints(", ifa_flags=");
	printflags(ifaddrflags, ifaddr.ifa_flags, "IFA_F_???");

	tprintf(", ifa_scope=%u, ifa_index=%d}", ifaddr.ifa_scope,
		ifaddr.ifa_index);
}

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
	switch (type)
	{
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_GETLINK:
	case RTM_SETLINK:
		decode_rtnetlink_link(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_link_attr, "IFLA_???");
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_GETADDR:
	case RTM_GETMULTICAST:
	case RTM_GETANYCAST:
		decode_rtnetlink_addr(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_addr_attr, "IFA_???");
		break;
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
	case RTM_GETROUTE:
	case RTM_NEWRULE:
	case RTM_DELRULE:
	case RTM_GETRULE:
		decode_rtnetlink_rtmsg(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_route_attr, "RTA_???");
		break;
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
	case RTM_GETNEIGH:
		decode_rtnetlink_neigh(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_neigh_attr, "NDA_???");
		break;
	case RTM_NEWNEIGHTBL:
	case RTM_GETNEIGHTBL:
	case RTM_SETNEIGHTBL:
		decode_rtnetlink_neightbl(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_neightbl_attr, "NDTA_???");
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
		len = decode_nlattr(tcp, addr, len, rtnetlink_tc_attr, "TCA_???");
		break;
	case RTM_NEWACTION:
	case RTM_DELACTION:
	case RTM_GETACTION:
		decode_rtnetlink_action(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_action_attr, "TCA_ACT_???");
		break;
	case RTM_NEWADDRLABEL:
	case RTM_DELADDRLABEL:
	case RTM_GETADDRLABEL:
		decode_rtnetlink_addrlbl(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_addrlabel_attr, "IFAL_???");
		break;
	case RTM_GETDCB:
	case RTM_SETDCB:
		decode_rtnetlink_dcb(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_dcb_attr, "DCB_ATTR_???");
		break;
	case RTM_GETNETCONF:
	case RTM_NEWNETCONF:
		decode_rtnetlink_ncm(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_nc_attr, "NETCONFA_???");
		break;
	case RTM_NEWMDB:
	case RTM_DELMDB:
	case RTM_GETMDB:
		decode_rtnetlink_mdb(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_mdb_attr, "MDBA_???");
		break;
	case RTM_NEWNSID:
	case RTM_DELNSID:
	case RTM_GETNSID:
		decode_rtnetlink_rtgenmsg(tcp, &addr, &len);
		len = decode_nlattr(tcp, addr, len, rtnetlink_nsid_attr, "NETNSA_???");
		break;
	}

	if (NETLINK_ALIGN_INF(len)) {
		tprints(", ");
		printstr(tcp, addr, len);
	}
}
