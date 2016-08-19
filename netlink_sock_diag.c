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
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/netlink_diag.h>
#include <linux/rtnetlink.h>
#define MAX_ADDR_LEN 32
#include <linux/packet_diag.h>
#include <linux/unix_diag.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
/* protocols */
#include "xlat/netlink_protocols.h"
#include "xlat/inet_protocols.h"
#include "xlat/if_ether.h"
/* show attributes */
#include "xlat/netlink_diag_show.h"
#include "xlat/unix_diag_show.h"
#include "xlat/packet_diag_show.h"
/* types */
#include "xlat/netlink_types.h"
/* attr */
#include "xlat/netlink_attr_ndiag.h"
#include "xlat/netlink_attr_idiag.h"
#include "xlat/netlink_attr_udiag.h"
#include "xlat/netlink_attr_pdiag.h"

static void
decode_inet_diag_sockid(struct tcb *tcp, int family,
			struct inet_diag_sockid *sockid)
{
	socklen_t text_size;
	socklen_t data_size;
	static const char zero_addr[sizeof(struct in6_addr)];

	switch(family) {
	case AF_INET:
		text_size = INET_ADDRSTRLEN;
		data_size = sizeof(struct in_addr);
		break;
	case AF_INET6:
		text_size = INET6_ADDRSTRLEN;
		data_size = sizeof(struct in6_addr);
		break;
	default:
		return;
	}
	char src_buf[text_size];
	char dst_buf[data_size];

	if (!inet_ntop(family, &sockid->idiag_src, src_buf, text_size))
		return;

	tprintf(", id={idiag_sport=%u, idiag_dport=%u", ntohs(sockid->idiag_sport),
		ntohs(sockid->idiag_dport));

	tprintf(", idiag_src=%s", src_buf);

	if (sockid->idiag_dport ||
	    memcmp(zero_addr, sockid->idiag_dst, data_size)) {
		if (!inet_ntop(family, &sockid->idiag_dst, dst_buf, text_size))
			tprintf(", idiag_dst=0");
		else
			tprintf(", idiag_dst=%s", dst_buf);
	} else {
		tprintf(", idiag_dst=0");
	}
	tprintf(", idiag_if=%u, idiag_cookie={%u, %u}}", sockid->idiag_if,
		sockid->idiag_cookie[0], sockid->idiag_cookie[1]);
}

static void
decode_inet_diag_req(struct tcb *tcp, unsigned long addr,
				      unsigned long len)
{
	struct inet_diag_req_v2 idiag_req;
	memset(&idiag_req, 0, sizeof(idiag_req));
	if (umove_or_printaddr(tcp, addr, &idiag_req) == -1)
		return;

	tprints(", {sdiag_family=");
	printxval(addrfams, idiag_req.sdiag_family, "AF_???");
	tprints(", sdiag_protocol=");
	printxval(inet_protocols, idiag_req.sdiag_protocol, "IPPROTO_???");
	tprintf(", idiag_ext=%u, idiag_states=%u", idiag_req.idiag_ext,
		idiag_req.idiag_states);

	decode_inet_diag_sockid(tcp, idiag_req.sdiag_family,
				&idiag_req.id);

	tprintf("}");
}

static void
decode_inet_diag_req_compat(struct tcb *tcp, unsigned long addr,
			                     unsigned long len)
{
	struct inet_diag_req idiag_req;
	memset(&idiag_req, 0, sizeof(idiag_req));
	if (umove_or_printaddr(tcp, addr, &idiag_req) == -1)
		return;

	tprints(", {idiag_family=");
	printxval(addrfams, idiag_req.idiag_family, "AF_???");
	tprintf(", idiag_src_len=%u, idiag_dst_len=%u",
		idiag_req.idiag_src_len, idiag_req.idiag_dst_len);
	tprintf(", idiag_ext=%u", idiag_req.idiag_ext);

	decode_inet_diag_sockid(tcp, idiag_req.idiag_family,
				&idiag_req.id);

	tprintf(", idiag_states=%u, idiag_dbs=%u}",
		idiag_req.idiag_states, idiag_req.idiag_dbs);
}

static void
decode_inet_diag_msg(struct tcb *tcp, unsigned long addr,
				      unsigned long len)
{
	struct inet_diag_msg idiag_msg;
	memset(&idiag_msg, 0, sizeof(idiag_msg));
	if (umove_or_printaddr(tcp, addr, &idiag_msg) == -1)
		return;

	tprints(", {idiag_family=");
	printxval(addrfams, idiag_msg.idiag_family, "AF_???");
	tprintf(", idiag_state=%u, idiag_timer=%u, idiag_retrans=%u",
		idiag_msg.idiag_state, idiag_msg.idiag_timer,
		idiag_msg.idiag_retrans);

	decode_inet_diag_sockid(tcp, idiag_msg.idiag_family,
				&idiag_msg.id);

	tprintf(", idiag_expires=%u, idiag_rqueue=%u, idiag_wqueue=%u"
		", idiag_uid=%u, idiag_inode=%u}",
		idiag_msg.idiag_expires, idiag_msg.idiag_rqueue,
		idiag_msg.idiag_wqueue, idiag_msg.idiag_uid,
		idiag_msg.idiag_inode);

	decode_nlattr(tcp, addr + sizeof(struct inet_diag_msg),
		      len - sizeof(struct inet_diag_msg), netlink_attr_idiag,
		      NULL, "INET_DIAG_???");
}

static void
decode_netlink_diag_req(struct tcb *tcp, unsigned long addr,
			unsigned long len)
{
	struct netlink_diag_req ndiag_req;
	memset(&ndiag_req, 0, sizeof(ndiag_req));
	if (umove_or_printaddr(tcp, addr, &ndiag_req) == -1)
		return;

	tprints(", {sdiag_family=");
	printxval(addrfams, ndiag_req.sdiag_family, "AF_???");
	tprints(", sdiag_protocol=");
	if (NDIAG_PROTO_ALL == ndiag_req.sdiag_protocol)
		tprints("NDIAG_PROTO_ALL");
	else
		printxval(netlink_protocols, ndiag_req.sdiag_protocol,
			  "NETLINK_???");
	tprintf(", ndiag_ino=%u, ndiag_show=", ndiag_req.ndiag_ino);
	printflags(netlink_diag_show, ndiag_req.ndiag_show, "NDIAG_SHOW_???");

	tprintf(", ndiag_cookie={%u, %u}}", ndiag_req.ndiag_cookie[0],
		ndiag_req.ndiag_cookie[1]);
}

static void
decode_netlink_diag_msg(struct tcb *tcp, unsigned long addr,
			unsigned long len)
{
	struct netlink_diag_msg ndiag_msg;

	memset(&ndiag_msg, 0, sizeof(ndiag_msg));
	if (umove_or_printaddr(tcp, addr, &ndiag_msg) == -1)
		return;

	tprints(", {ndiag_family=");
	printxval(addrfams, ndiag_msg.ndiag_family, "AF_???");
	tprintf(", ndiag_type=%u", ndiag_msg.ndiag_type);

	tprints(", ndiag_protocol=");

	printxval(netlink_protocols, ndiag_msg.ndiag_protocol,
			  "NETLINK_???");
	tprintf(", ndiag_state=%u", ndiag_msg.ndiag_state);

	tprintf(", ndiag_portid=%u, ndiag_dst_portid=%u, ndiag_dst_group=%u",
		ndiag_msg.ndiag_portid, ndiag_msg.ndiag_dst_portid,
		ndiag_msg.ndiag_dst_group);

	tprintf(", ndiag_ino=%u, ndiag_cookie={%u, %u}}", ndiag_msg.ndiag_ino,
		ndiag_msg.ndiag_cookie[0], ndiag_msg.ndiag_cookie[1]);

	decode_nlattr(tcp, addr + sizeof(struct netlink_diag_msg),
		      len - sizeof(struct netlink_diag_msg), netlink_attr_ndiag,
		      NULL, "NETLINK_DIAG_???");
}

static void
decode_packet_diag_req(struct tcb *tcp, unsigned long addr,
		       unsigned long len)
{
	struct packet_diag_req pdiag_req;
	memset(&pdiag_req, 0, sizeof(pdiag_req));
	if (umove_or_printaddr(tcp, addr, &pdiag_req) == -1)
		return;

	tprints(", {sdiag_family=");
	printxval(addrfams, pdiag_req.sdiag_family, "AF_???");
	tprints(", sdiag_protocol=");
	printxval(if_ether, pdiag_req.sdiag_protocol, "ETH_P_???");

	tprintf(", pdiag_ino=%u, pdiag_show=", pdiag_req.pdiag_ino);

	printflags(packet_diag_show, pdiag_req.pdiag_show, "PACKET_SHOW_???");

	tprintf(", pdiag_cookie={%u, %u}}", pdiag_req.pdiag_cookie[0],
		pdiag_req.pdiag_cookie[1]);
}

static void
decode_packet_diag_msg(struct tcb *tcp, unsigned long addr,
		       unsigned long len)
{
	struct packet_diag_msg pdiag_msg;
	memset(&pdiag_msg, 0, sizeof(pdiag_msg));
	if (umove_or_printaddr(tcp, addr, &pdiag_msg) == -1)
		return;

	tprints(", {pdiag_family=");
	printxval(addrfams, pdiag_msg.pdiag_family, "AF_???");

	tprintf(", pdiag_type=%u, pdiag_num=%u, pdiag_ino=%u"
		", pdiag_cookie={%u, %u}}", pdiag_msg.pdiag_type,
		pdiag_msg.pdiag_num, pdiag_msg.pdiag_ino,
		pdiag_msg.pdiag_cookie[0], pdiag_msg.pdiag_cookie[1]);

	decode_nlattr(tcp, addr + sizeof(struct packet_diag_msg),
		      len - sizeof(struct packet_diag_msg), netlink_attr_pdiag,
		      NULL, "PACKET_DIAG_???");
}

static void
decode_unix_diag_req(struct tcb *tcp, unsigned long addr,
		     unsigned long len)
{
	struct unix_diag_req udiag_req;
	memset(&udiag_req, 0, sizeof(udiag_req));
	if (umove_or_printaddr(tcp, addr, &udiag_req) == -1)
		return;

	tprints(", {sdiag_family=");
	printxval(addrfams, udiag_req.sdiag_family, "AF_???");
	tprintf(", sdiag_protocol=%d", udiag_req.sdiag_protocol);

	tprintf(", udiag_states=%u, udiag_ino=%u, udiag_show=",
		udiag_req.udiag_states, udiag_req.udiag_ino);

	printflags(unix_diag_show, udiag_req.udiag_show, "UDIAG_SHOW_???");

	tprintf(", udiag_cookie={%u, %u}}", udiag_req.udiag_cookie[0],
		udiag_req.udiag_cookie[1]);
}

static void
decode_unix_diag_msg(struct tcb *tcp, unsigned long addr,
		     unsigned long len)
{
	struct unix_diag_msg udiag_msg;
	memset(&udiag_msg, 0, sizeof(udiag_msg));
	if (umove_or_printaddr(tcp, addr, &udiag_msg) == -1)
		return;

	tprints(", {udiag_family=");
	printxval(addrfams, udiag_msg.udiag_family, "AF_???");
	tprintf(", udiag_type=%u", udiag_msg.udiag_type);

	tprintf(", udiag_state=%u, udiag_ino=%u, udiag_cookie={%u, %u}}",
		udiag_msg.udiag_state, udiag_msg.udiag_ino,
		udiag_msg.udiag_cookie[0], udiag_msg.udiag_cookie[1]);

	decode_nlattr(tcp, addr + sizeof(struct unix_diag_msg),
		      len - sizeof(struct unix_diag_msg), netlink_attr_udiag,
		      NULL, "UNIX_DIAG_???");
}

void
decode_netlink_sock_diag(struct tcb *tcp, unsigned long addr,
			 unsigned long len, unsigned int type, int is_req)
{
	unsigned char family;
	if (umove(tcp, addr, &family)) {
		tprints(", ");
		printstr(tcp, addr, len);
		return;
	}

	switch(family)
	{
	case AF_INET6:
	case AF_INET:
		if (is_req) {
			if (type == TCPDIAG_GETSOCK ||
			    type == DCCPDIAG_GETSOCK)
				decode_inet_diag_req_compat(tcp, addr, len);
			else
				decode_inet_diag_req(tcp, addr, len);
		} else
			decode_inet_diag_msg(tcp, addr, len);
		break;
	case AF_NETLINK:
		if (is_req)
			decode_netlink_diag_req(tcp, addr, len);
		else
			decode_netlink_diag_msg(tcp, addr, len);
		break;
	case AF_PACKET:
		if (is_req)
			decode_packet_diag_req(tcp, addr, len);
		else
			decode_packet_diag_msg(tcp, addr, len);
		break;
	case AF_UNIX:
		if (is_req)
			decode_unix_diag_req(tcp, addr, len);
		else
			decode_unix_diag_msg(tcp, addr, len);
		break;
	default:
		tprints(", ");
		printstr(tcp, addr, len);
	}
}
