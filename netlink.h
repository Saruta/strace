#ifndef NETLINK_H_
# define NETLINK_H_

#include <linux/netlink.h>

#define NETLINK_ALIGN_INF(len) ((len) & ~(NLA_ALIGNTO - 1))

#define NETLINK_ALIGN_UP(len) (((len-1) & ~(NLA_ALIGNTO - 1)) + NLA_ALIGNTO)

#endif /* NETLINK_H_*/
