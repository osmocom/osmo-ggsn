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

#ifndef _TUN_H
#define _TUN_H

#include <stdbool.h>
#include <net/if.h>

#include <osmocom/core/netdev.h>
#include <osmocom/core/tun.h>

#include "../lib/in46_addr.h"

#define PACKET_MAX      8196	/* Maximum packet size we receive */
#define TUN_SCRIPTSIZE   256
#define TUN_ADDRSIZE     128

#include "config.h"
#include "netdev.h"

/* ***********************************************************
 * Information storage for each tun instance
 *************************************************************/

struct tun_t {
	/* In tun device mode: operates on the tun interface, owned by tun.tundev below.
	 * In gtp kernel mode: operates on the gtp device, allocated explicitly */
	struct osmo_netdev *netdev;
	struct in46_addr addr;
	struct in_addr netmask;
	int addrs;		/* Number of allocated IP addresses */
	char devname[IFNAMSIZ];	/* Name of the tun device */
	int (*cb_ind) (struct tun_t * tun, void *pack, unsigned len);
	/* to be used by libgtp callers/users (to attach their own private state) */
	void *priv;
	/* Fields only in use when using the tun device mode: */
	struct {
		struct osmo_tundev *tundev; /* Manages the tun interface; NULL on gtp kernel mode */
		int fd; /* File descriptor to tun interface; -1 on gtp kernel mode */
	} tundev;
};

extern struct tun_t *tun_alloc_tundev(const char *devname);
extern struct tun_t *tun_alloc_gtpdev(const char *devname, int fd0, int fd1u);
extern int tun_free(struct tun_t *tun);
extern int tun_inject_pkt(struct tun_t *tun, void *pack, unsigned len);

extern int tun_addaddr(struct tun_t *this, struct in46_addr *addr, size_t prefixlen);

extern int tun_set_cb_ind(struct tun_t *this,
			  int (*cb_ind) (struct tun_t * tun, void *pack,
					 unsigned len));

extern int tun_runscript(struct tun_t *tun, char *script);

int tun_ip_local_get(const struct tun_t *tun, struct in46_prefix *prefix_list,
		     size_t prefix_size, int flags);

#define LOGTUN(level, tun, fmt, args...) \
	LOGP(DTUN, level, "TUN(%s): " fmt, (tun)->devname, ## args)

#endif /* !_TUN_H */
