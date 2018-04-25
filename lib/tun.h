/*
 * TUN interface functions.
 * Copyright (C) 2002, 2003 Mondru AB.
 * Copyright (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#ifndef _TUN_H
#define _TUN_H

#include <net/if.h>

#include "../lib/in46_addr.h"

#define PACKET_MAX      8196	/* Maximum packet size we receive */
#define TUN_SCRIPTSIZE   256
#define TUN_ADDRSIZE     128
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

/* ***********************************************************
 * Information storage for each tun instance
 *************************************************************/

struct tun_t {
	int fd;			/* File descriptor to tun interface */
	struct in_addr addr;
	struct in_addr dstaddr;
	struct in_addr netmask;
	int addrs;		/* Number of allocated IP addresses */
	int routes;		/* One if we allocated an automatic route */
	char devname[IFNAMSIZ];	/* Name of the tun device */
	int (*cb_ind) (struct tun_t * tun, void *pack, unsigned len);
	/* to be used by libgtp callers/users (to attach their own private state) */
	void *priv;
};

extern int tun_new(struct tun_t **tun, const char *dev_name);
extern int tun_free(struct tun_t *tun);
extern int tun_decaps(struct tun_t *this);
extern int tun_encaps(struct tun_t *tun, void *pack, unsigned len);

extern int tun_addaddr(struct tun_t *this, struct in46_addr *addr,
		       struct in46_addr *dstaddr, size_t prefixlen);

extern int tun_setaddr(struct tun_t *this, struct in46_addr *our_adr,
		       struct in46_addr *his_adr, size_t prefixlen);

int netdev_addroute(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask);

extern int tun_set_cb_ind(struct tun_t *this,
			  int (*cb_ind) (struct tun_t * tun, void *pack,
					 unsigned len));

extern int tun_runscript(struct tun_t *tun, char *script);

int netdev_ip_local_get(const char *devname, struct in46_prefix *prefix_list,
			size_t prefix_size, int flags);

int tun_ip_local_get(const struct tun_t *tun, struct in46_prefix *prefix_list,
		     size_t prefix_size, int flags);

#endif /* !_TUN_H */
