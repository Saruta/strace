#ifndef NETLINK_H_
# define NETLINK_H_

#include <linux/netlink.h>

#define NETLINK_ALIGN_INF(len) ((len) & ~(NLA_ALIGNTO - 1))

#endif /* NETLINK_H_*/
