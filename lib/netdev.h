#pragma once
/*
 * TUN interface functions.
 * Copyright (C) 2002, 2003 Mondru AB.
 * Copyright (C) 2017-2018 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#include <net/if.h>

#include "../lib/in46_addr.h"

#define TUN_NLBUFSIZE   1024

#include "config.h"

/* ipv6 ip type flags for tun_ipv6_local_get() */
enum {
	IP_TYPE_IPv4 = 1,
	IP_TYPE_IPv6_LINK = 2,
	IP_TYPE_IPv6_NONLINK = 4,
};
#define IP_TYPE_IPv6 (IP_TYPE_IPv6_LINK | IP_TYPE_IPv6_NONLINK)


#ifndef HAVE_IPHDR
struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };
#endif /* !HAVE_IPHDR */

extern int netdev_setaddr4(const char *devname, struct in_addr *addr,
			   struct in_addr *dstaddr, struct in_addr *netmask);

extern int netdev_setaddr6(const char *devname, struct in6_addr *addr, struct in6_addr *dstaddr,
			   size_t prefixlen);

extern int netdev_addaddr4(const char *devname, struct in_addr *addr,
			   struct in_addr *dstaddr, struct in_addr *netmask);

extern int netdev_addaddr6(const char *devname, struct in6_addr *addr,
			   struct in6_addr *dstaddr, int prefixlen);

extern int netdev_addroute4(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask);
extern int netdev_delroute4(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask);

extern int netdev_ip_local_get(const char *devname, struct in46_prefix *prefix_list,
				size_t prefix_size, int flags);
