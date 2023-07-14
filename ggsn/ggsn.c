/*
 * OsmoGGSN - Gateway GPRS Support Node
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 * Copyright (C) 2017-2019 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/* ggsn.c
 *
 */

#ifdef __linux__
#define _GNU_SOURCE 1		/* strdup() prototype, broken arpa/inet.h */
#endif

#include "../config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <getopt.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>

#include <osmocom/core/timer.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/gsm/apn.h>

#include "../lib/tun.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "../lib/in46_addr.h"
#include "../lib/gtp-kernel.h"
#include "../lib/util.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "../lib/icmpv6.h"
#include "pco.h"
#include "ggsn.h"

static int ggsn_tun_fd_cb(struct osmo_fd *fd, unsigned int what);
static int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len);

void ggsn_close_one_pdp(struct pdp_t *pdp)
{
	LOGPPDP(LOGL_DEBUG, pdp, "Sending DELETE PDP CTX due to shutdown\n");
	gtp_delete_context_req2(pdp->gsn, pdp, NULL, 1);
	/* We have nothing more to do with pdp ctx, free it. Upon cb_delete_context
	   called during this call we'll clean up ggsn related stuff attached to this
	   pdp context. After this call, ippool member is cleared so
	   data is no longer valid and should not be accessed anymore. */
	gtp_freepdp_teardown(pdp->gsn, pdp);
}

static void pool_close_all_pdp(struct ippool_t *pool)
{
	unsigned int i;

	if (!pool)
		return;

	for (i = 0; i < pool->listsize; i++) {
		struct ippoolm_t *member = &pool->member[i];
		struct pdp_t *pdp;

		if (!member->inuse)
			continue;
		pdp = member->peer;
		if (!pdp)
			continue;
		ggsn_close_one_pdp(pdp);
	}
}

int apn_stop(struct apn_ctx *apn)
{
	LOGPAPN(LOGL_NOTICE, apn, "Stopping\n");
	/* check if pools have any active PDP contexts and bail out */
	pool_close_all_pdp(apn->v4.pool);
	pool_close_all_pdp(apn->v6.pool);

	/* shutdown whatever old state might be left */
	if (apn->tun.tun) {
		/* run ip-down script */
		if (apn->tun.cfg.ipdown_script) {
			LOGPAPN( LOGL_INFO, apn, "Running %s\n", apn->tun.cfg.ipdown_script);
			tun_runscript(apn->tun.tun, apn->tun.cfg.ipdown_script);
		}
		if (apn->cfg.gtpu_mode == APN_GTPU_MODE_TUN) {
			/* release tun device */
			LOGPAPN(LOGL_INFO, apn, "Closing TUN device %s\n", apn->tun.tun->devname);
			osmo_fd_unregister(&apn->tun.fd);
		}
		tun_free(apn->tun.tun);
		apn->tun.tun = NULL;
	}

	if (apn->v4.pool) {
		LOGPAPN(LOGL_INFO, apn, "Releasing IPv4 pool\n");
		ippool_free(apn->v4.pool);
		apn->v4.pool = NULL;
	}
	if (apn->v6.pool) {
		LOGPAPN(LOGL_INFO, apn, "Releasing IPv6 pool\n");
		ippool_free(apn->v6.pool);
		apn->v6.pool = NULL;
	}

	apn->started = false;
	return 0;
}


static int alloc_ippool_blacklist(struct apn_ctx *apn, struct in46_prefix **blacklist, bool ipv6)
{

	int flags, len, len2, i;

	*blacklist = NULL;

	if (ipv6)
		flags = IP_TYPE_IPv6_NONLINK;
	else
		flags = IP_TYPE_IPv4;

	while (1) {
		len = netdev_ip_local_get(apn->tun.cfg.dev_name, NULL, 0, flags);
		if (len < 1)
			return len;

		*blacklist = talloc_zero_size(apn, len * sizeof(struct in46_prefix));
		len2 = netdev_ip_local_get(apn->tun.cfg.dev_name, *blacklist, len, flags);
		if (len2 < 1) {
			talloc_free(*blacklist);
			*blacklist = NULL;
			return len2;
		}

		if (len2 > len) { /* iface was added between 2 calls, repeat operation */
			talloc_free(*blacklist);
			*blacklist = NULL;
		} else
			break;
	}

	for (i = 0; i < len2; i++)
		LOGPAPN(LOGL_INFO, apn, "Blacklist tun IP %s\n",
			in46p_ntoa(&(*blacklist)[i]));

	return len2;
}

/* actually start the APN with its current config */
int apn_start(struct apn_ctx *apn)
{
	int ippool_flags = IPPOOL_NONETWORK | IPPOOL_NOBROADCAST;
	struct in46_prefix ipv6_tun_linklocal_ip;
	struct in46_prefix *blacklist;
	int blacklist_size;
	struct gsn_t *gsn = apn->ggsn->gsn;
	int rc;

	if (apn->started)
		return 0;

	LOGPAPN(LOGL_INFO, apn, "Starting\n");
	switch (apn->cfg.gtpu_mode) {
	case APN_GTPU_MODE_TUN:
		LOGPAPN(LOGL_INFO, apn, "Opening TUN device %s\n", apn->tun.cfg.dev_name);
		if (tun_new(&apn->tun.tun, apn->tun.cfg.dev_name, false, -1, -1)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to configure tun device\n");
			return -1;
		}
		LOGPAPN(LOGL_INFO, apn, "Opened TUN device %s\n", apn->tun.tun->devname);

		/* Register with libosmcoore */
		osmo_fd_setup(&apn->tun.fd, apn->tun.tun->fd, OSMO_FD_READ, ggsn_tun_fd_cb, apn, 0);
		osmo_fd_register(&apn->tun.fd);

		/* Set TUN library callback */
		tun_set_cb_ind(apn->tun.tun, cb_tun_ind);
		break;
	case APN_GTPU_MODE_KERNEL_GTP:
		LOGPAPN(LOGL_INFO, apn, "Opening Kernel GTP device %s\n", apn->tun.cfg.dev_name);
		if (apn->cfg.apn_type_mask & (APN_TYPE_IPv6|APN_TYPE_IPv4v6)) {
			LOGPAPN(LOGL_ERROR, apn, "Kernel GTP currently supports only IPv4\n");
			apn_stop(apn);
			return -1;
		}
		if (gsn == NULL) {
			/* skip bringing up the APN now if the GSN is not initialized yet.
			 * This happens during initial load of the config file, as the
			 * "no shutdown" in the ggsn node only happens after the "apn" nodes
			 * are brought up */
			LOGPAPN(LOGL_NOTICE, apn, "Skipping APN start\n");
			return 0;
		}
		/* use GTP kernel module for data packet encapsulation */
		if (tun_new(&apn->tun.tun, apn->tun.cfg.dev_name, true, gsn->fd0, gsn->fd1u)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to configure Kernel GTP device\n");
			return -1;
		}
		break;
	default:
		LOGPAPN(LOGL_ERROR, apn, "Unknown GTPU Mode %d\n", apn->cfg.gtpu_mode);
		return -1;
	}

	/* common initialization below */

	/* set back-pointer from TUN device to APN */
	apn->tun.tun->priv = apn;

	if (apn->v4.cfg.ifconfig_prefix.addr.len) {
		LOGPAPN(LOGL_INFO, apn, "Setting tun IP address %s\n",
			in46p_ntoa(&apn->v4.cfg.ifconfig_prefix));
		if (tun_addaddr(apn->tun.tun, &apn->v4.cfg.ifconfig_prefix.addr, NULL,
				apn->v4.cfg.ifconfig_prefix.prefixlen)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to set tun IPv4 address %s: %s\n",
				in46p_ntoa(&apn->v4.cfg.ifconfig_prefix), strerror(errno));
			apn_stop(apn);
			return -1;
		}
	}

	if (apn->v6.cfg.ifconfig_prefix.addr.len) {
		LOGPAPN(LOGL_INFO, apn, "Setting tun IPv6 address %s\n",
			in46p_ntoa(&apn->v6.cfg.ifconfig_prefix));
		if (tun_addaddr(apn->tun.tun, &apn->v6.cfg.ifconfig_prefix.addr, NULL,
				apn->v6.cfg.ifconfig_prefix.prefixlen)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to set tun IPv6 address %s: %s. "
				"Ensure you have ipv6 support and not used the disable_ipv6 sysctl?\n",
				in46p_ntoa(&apn->v6.cfg.ifconfig_prefix), strerror(errno));
			apn_stop(apn);
			return -1;
		}
	}

	if (apn->v6.cfg.ll_prefix.addr.len) {
		LOGPAPN(LOGL_INFO, apn, "Setting tun IPv6 link-local address %s\n",
			in46p_ntoa(&apn->v6.cfg.ll_prefix));
		if (tun_addaddr(apn->tun.tun, &apn->v6.cfg.ll_prefix.addr, NULL,
				apn->v6.cfg.ll_prefix.prefixlen)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to set tun IPv6 link-local address %s: %s. "
				"Ensure you have ipv6 support and not used the disable_ipv6 sysctl?\n",
				in46p_ntoa(&apn->v6.cfg.ll_prefix), strerror(errno));
			apn_stop(apn);
			return -1;
		}
		apn->v6_lladdr = apn->v6.cfg.ll_prefix.addr.v6;
	}

	if (apn->tun.cfg.ipup_script) {
		LOGPAPN(LOGL_INFO, apn, "Running ip-up script %s\n",
			apn->tun.cfg.ipup_script);
		tun_runscript(apn->tun.tun, apn->tun.cfg.ipup_script);
	}

	if (apn->cfg.apn_type_mask & (APN_TYPE_IPv6|APN_TYPE_IPv4v6) &&
	    apn->v6.cfg.ll_prefix.addr.len == 0) {
		rc = tun_ip_local_get(apn->tun.tun, &ipv6_tun_linklocal_ip, 1, IP_TYPE_IPv6_LINK);
		if (rc < 1) {
			LOGPAPN(LOGL_ERROR, apn, "Cannot obtain IPv6 link-local address of interface: %s\n",
				rc ? strerror(errno) : "tun interface has no link-local IP assigned");
			apn_stop(apn);
			return -1;
		}
		apn->v6_lladdr = ipv6_tun_linklocal_ip.addr.v6;
	}

	/* Create IPv4 pool */
	if (apn->v4.cfg.dynamic_prefix.addr.len) {
		LOGPAPN(LOGL_INFO, apn, "Creating IPv4 pool %s\n",
			in46p_ntoa(&apn->v4.cfg.dynamic_prefix));
		if ((blacklist_size = alloc_ippool_blacklist(apn, &blacklist, false)) < 0)
			LOGPAPN(LOGL_ERROR, apn, "Failed obtaining IPv4 tun IPs\n");
		if (ippool_new(&apn->v4.pool, &apn->v4.cfg.dynamic_prefix,
				&apn->v4.cfg.static_prefix, ippool_flags,
				blacklist, blacklist_size)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to create IPv4 pool\n");
			talloc_free(blacklist);
			apn_stop(apn);
			return -1;
		}
		talloc_free(blacklist);
	}

	/* Create IPv6 pool */
	if (apn->v6.cfg.dynamic_prefix.addr.len) {
		LOGPAPN(LOGL_INFO, apn, "Creating IPv6 pool %s\n",
			in46p_ntoa(&apn->v6.cfg.dynamic_prefix));
		if ((blacklist_size = alloc_ippool_blacklist(apn, &blacklist, true)) < 0)
			LOGPAPN(LOGL_ERROR, apn, "Failed obtaining IPv6 tun IPs\n");
		if (ippool_new(&apn->v6.pool, &apn->v6.cfg.dynamic_prefix,
				&apn->v6.cfg.static_prefix, ippool_flags,
				blacklist, blacklist_size)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to create IPv6 pool\n");
			talloc_free(blacklist);
			apn_stop(apn);
			return -1;
		}
		talloc_free(blacklist);
	}

	LOGPAPN(LOGL_NOTICE, apn, "Successfully started\n");
	apn->started = true;
	return 0;
}

static struct imsi_map_entry *apn_imsi_map_lookup_by_imsi(const char *imsi, const struct apn_ctx_ip *ctx)
{
	struct imsi_map_entry *map;
	llist_for_each_entry(map, &ctx->imsi_ip_map, list) {
		if (!strcmp(imsi, map->imsi))
			return map;
	}
	return NULL;
}

static struct imsi_map_entry *apn_imsi_map_lookup_by_ip(const struct in46_addr *addr, const struct apn_ctx_ip *ctx)
{
	struct imsi_map_entry *map;
	if (!addr)
		return NULL;
	llist_for_each_entry(map, &ctx->imsi_ip_map, list) {
		if (in46a_equal(addr, &map->addr))
			return map;
	}
	return NULL;
}

int apn_imsi_ip_map_add(const char *imsi, const char *ip, struct apn_ctx_ip *ctx)
{
	struct imsi_map_entry *map;
	struct in46_addr addr = { 0 };
	size_t t;

	if (ippool_aton(&addr, &t, ip, 0))
		return -EINVAL;
	if (apn_imsi_map_lookup_by_imsi(imsi, ctx) || apn_imsi_map_lookup_by_ip(&addr, ctx))
		return -EEXIST;

	map = talloc_zero(NULL, struct imsi_map_entry);
	if (!map)
		return -ENOMEM;
	if (ippool_aton(&map->addr, &t, ip, 0)) {
		talloc_free(map);
		return -EINVAL;
	}

	osmo_strlcpy(map->imsi, imsi, sizeof(map->imsi));
	llist_add(&map->list, &ctx->imsi_ip_map);

	return 0;
}

int apn_imsi_ip_map_del(const char *imsi, const char *ip, struct apn_ctx_ip *ctx)
{
	struct imsi_map_entry *map;

	map = apn_imsi_map_lookup_by_imsi(imsi, ctx);
	if (!map)
		return -ENODEV;

	llist_del(&map->list);
	talloc_free(map);

	return 0;
}

static struct imsi_map_entry *imsi_has_reserved_ip(const char *imsi, struct apn_ctx_ip *ctx)
{
	if (llist_empty(&ctx->imsi_ip_map))
		return NULL;
	return apn_imsi_map_lookup_by_imsi(imsi, ctx);
}

static bool send_trap(const struct gsn_t *gsn, const struct pdp_t *pdp, const struct ippoolm_t *member, const char *var)
{
	char addrbuf[256];
	char val[NAMESIZE];

	const char *addrstr = in46a_ntop(&member->addr, addrbuf, sizeof(addrbuf));

	snprintf(val, sizeof(val), "%s,%s", imsi_gtp2str(&pdp->imsi), addrstr);

	if (ctrl_cmd_send_trap(g_ctrlh, var, val) < 0) {
		LOGPPDP(LOGL_ERROR, pdp, "Failed to create and send TRAP %s\n", var);
		return false;
	}
	return true;
}

static int delete_context(struct pdp_t *pdp)
{
	struct gsn_t *gsn = pdp->gsn;
	struct pdp_priv_t *pdp_priv = pdp->priv;
	struct apn_ctx *apn;
	struct ippoolm_t *member;
	int i;

	LOGPPDP(LOGL_INFO, pdp, "Deleting PDP context\n");

	for (i = 0; i < 2; i++) {
		if (pdp->peer[i]) {
			member = pdp->peer[i];
			send_trap(gsn, pdp, member, "imsi-rem-ip"); /* TRAP with IP removal */
			ippool_freeip(member->pool, member);
		} else if (i == 0) {
			LOGPPDP(LOGL_ERROR, pdp, "Cannot find/free IP Pool member\n");
		}
	}

	if (!pdp_priv) {
		LOGPPDP(LOGL_NOTICE, pdp, "Deleting PDP context: without private structure!\n");
		return 0;
	}

	/* Remove from SGSN */
	sgsn_peer_remove_pdp_priv(pdp_priv);

	apn = pdp_priv->apn;
	if (apn && apn->cfg.gtpu_mode == APN_GTPU_MODE_KERNEL_GTP) {
		if (gtp_kernel_tunnel_del(pdp, apn->tun.cfg.dev_name)) {
			LOGPPDP(LOGL_ERROR, pdp, "Cannot delete tunnel from kernel:%s\n",
				strerror(errno));
		}
	}

	talloc_free(pdp_priv);

	return 0;
}

bool apn_supports_ipv4(const struct apn_ctx *apn)
{
	if (apn->v4.cfg.static_prefix.addr.len  || apn->v4.cfg.dynamic_prefix.addr.len)
		return true;
	return false;
}

static bool apn_supports_ipv6(const struct apn_ctx *apn)
{
	if (apn->v6.cfg.static_prefix.addr.len  || apn->v6.cfg.dynamic_prefix.addr.len)
		return true;
	return false;
}

static struct sgsn_peer* ggsn_find_sgsn(struct ggsn_ctx *ggsn, struct in_addr *peer_addr)
{
	struct sgsn_peer *sgsn;

	llist_for_each_entry(sgsn, &ggsn->sgsn_list, entry) {
		if (memcmp(&sgsn->addr, peer_addr, sizeof(*peer_addr)) == 0)
			return sgsn;
	}
	return NULL;
}

static struct sgsn_peer* ggsn_find_or_create_sgsn(struct ggsn_ctx *ggsn, struct pdp_t *pdp)
{
	struct sgsn_peer *sgsn;
	struct in_addr ia;

	if (gsna2in_addr(&ia, &pdp->gsnrc)) {
		LOGPPDP(LOGL_ERROR, pdp, "Failed parsing gsnrc (len=%u) to discover SGSN\n",
			pdp->gsnrc.l);
		return NULL;
	}

	if ((sgsn = ggsn_find_sgsn(ggsn, &ia)))
		return sgsn;

	sgsn = sgsn_peer_allocate(ggsn, &ia, pdp->version);
	llist_add(&sgsn->entry, &ggsn->sgsn_list);
	return sgsn;
}

int create_context_ind(struct pdp_t *pdp)
{
	static char name_buf[256];
	struct gsn_t *gsn = pdp->gsn;
	struct ggsn_ctx *ggsn = gsn->priv;
	struct in46_addr addr[2];
	struct ippoolm_t *member = NULL, *addrv4 = NULL, *addrv6 = NULL;
	char straddrv4[INET_ADDRSTRLEN], straddrv6[INET6_ADDRSTRLEN];
	struct apn_ctx *apn = NULL;
	int rc, num_addr, i;
	char *apn_name;
	struct sgsn_peer *sgsn;
	struct pdp_priv_t *pdp_priv;
	struct imsi_map_entry *imsi_map;

	apn_name = osmo_apn_to_str(name_buf, pdp->apn_req.v, pdp->apn_req.l);
	LOGPPDP(LOGL_DEBUG, pdp, "Processing create PDP context request for APN '%s'\n",
		apn_name ? name_buf : "(NONE)");

	/* First find an exact APN name match */
	if (apn_name != NULL)
		apn = ggsn_find_apn(ggsn, name_buf);
	/* ignore if the APN has not been started */
	if (apn && !apn->started)
		apn = NULL;

	/* then try default (if any) */
	if (!apn)
		apn = ggsn->cfg.default_apn;
	/* ignore if the APN has not been started */
	if (apn && !apn->started)
		apn = NULL;

	if (!apn) {
		/* no APN found for what user requested */
		LOGPPDP(LOGL_NOTICE, pdp, "Unknown APN '%s', rejecting\n", name_buf);
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_MISSING_APN);
		return 0;
	}

	/* FIXME: implement context request for static IP addresses! */
	if (pdp->eua.l > 2) {
		LOGPPDP(LOGL_ERROR, pdp, "Static IP addresses not supported: %s\n",
			osmo_hexdump(pdp->eua.v, pdp->eua.l));
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_NOT_SUPPORTED);
		return 0;
	}

	memcpy(pdp->qos_neg0, pdp->qos_req0, sizeof(pdp->qos_req0));

	memcpy(pdp->qos_neg.v, pdp->qos_req.v, pdp->qos_req.l);	/* TODO */
	pdp->qos_neg.l = pdp->qos_req.l;

	memset(addr, 0, sizeof(addr));
	if ((num_addr = in46a_from_eua(&pdp->eua, addr)) < 0) {
		LOGPPDP(LOGL_ERROR, pdp, "Cannot decode EUA from MS/SGSN: %s\n",
			osmo_hexdump(pdp->eua.v, pdp->eua.l));
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_UNKNOWN_PDP);
		return 0;
	}

	/* Store the actual APN for logging and the VTY */
	rc = osmo_apn_from_str(pdp->apn_use.v, sizeof(pdp->apn_use.v), apn->cfg.name);
	if (rc < 0) /* Unlikely this would happen, but anyway... */
		LOGPPDP(LOGL_ERROR, pdp, "Failed to store APN '%s'\n", apn->cfg.name);
	pdp->apn_use.l = rc;

	/* Check if we have a entry in the reserved IP map for this IMSI */
	imsi_map = imsi_has_reserved_ip(imsi_gtp2str(&pdp->imsi), &apn->v4);
	if (imsi_map) {
		/* Override (prefill) any requested (dynamic|static) IP
		 * in the EUA with the one from the configuration map. */
		addr[0].len = 4;
		memcpy(&addr[0].v4.s_addr, &imsi_map->addr.v4, 4);
		LOGPPDP(LOGL_INFO, pdp, "IMSI[%s] has an entry[%s] in reserved IP map\n",
			imsi_gtp2str(&pdp->imsi), in46a_ntoa(&imsi_map->addr));
	}

	/* Allocate dynamic addresses from the pool */
	for (i = 0; i < num_addr; i++) {
		if (in46a_is_v4(&addr[i])) {
			/* does this APN actually have an IPv4 pool? */
			if (!apn_supports_ipv4(apn))
				goto err_wrong_af;

			rc = ippool_newip(apn->v4.pool, &member, &addr[i], 0);

			if (!imsi_map) {
				/* This IMSI does not have a reserved IP, check that we did not assign one */
				while (apn_imsi_map_lookup_by_ip(&member->addr, &apn->v4)) {
					LOGPPDP(LOGL_INFO, pdp, "Returned IP[%s] is reserved, trying again.\n",
						in46a_ntoa(&member->addr));
					ippool_freeip(member->pool, member);
					rc = ippool_newip(apn->v4.pool, &member, &addr[i], 0);
				}

			}
			LOGPPDP(LOGL_INFO, pdp, "Got IP[%s] from the pool.\n", in46a_ntoa(&member->addr));
			if (rc < 0)
				goto err_pool_full;
			/* copy back */
			memcpy(&addr[i].v4.s_addr, &member->addr.v4, 4);

			addrv4 = member;

		} else if (in46a_is_v6(&addr[i])) {

			/* does this APN actually have an IPv6 pool? */
			if (!apn_supports_ipv6(apn))
				goto err_wrong_af;

			rc = ippool_newip(apn->v6.pool, &member, &addr[i], 0);
			if (rc < 0)
				goto err_pool_full;

			/* IPv6 doesn't really send the real/allocated address at this point, but just
			 * the link-identifier which the MS shall use for router solicitation */
			/* initialize upper 64 bits to prefix, they are discarded by MS anyway */
			memcpy(addr[i].v6.s6_addr, &member->addr.v6, 8);
			/* use allocated 64bit prefix as lower 64bit, used as link id by MS */
			memcpy(addr[i].v6.s6_addr+8, &member->addr.v6, 8);

			addrv6 = member;
		} else
			OSMO_ASSERT(0);

		pdp->peer[i] = member;
		member->peer = pdp;
	}

	in46a_to_eua(addr, num_addr, &pdp->eua);

	if (apn->cfg.gtpu_mode == APN_GTPU_MODE_KERNEL_GTP && apn_supports_ipv4(apn)) {
		/* TODO: In IPv6, EUA doesn't contain the actual IP addr/prefix! */
		if (gtp_kernel_tunnel_add(pdp, apn->tun.cfg.dev_name) < 0) {
			LOGPPDP(LOGL_ERROR, pdp, "Cannot add tunnel to kernel: %s\n", strerror(errno));
			gtp_create_context_resp(gsn, pdp, GTPCAUSE_SYS_FAIL);
			return 0;
		}
	}

	pdp->ipif = apn->tun.tun;	/* TODO */

	pdp_priv = talloc_zero(ggsn, struct pdp_priv_t);
	pdp->priv = pdp_priv;
	pdp_priv->lib = pdp;
	/* Create sgsn and assign pdp to it */
	sgsn = ggsn_find_or_create_sgsn(ggsn, pdp);
	sgsn_peer_add_pdp_priv(sgsn, pdp_priv);
	pdp_priv->apn = apn;

	/* TODO: change trap to send 2 IPs */
	if (!send_trap(gsn, pdp, member, "imsi-ass-ip")) { /* TRAP with IP assignment */
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_NO_RESOURCES);
		return 0;
	}

	process_pco(apn, pdp);

	/* Transmit G-PDU sequence numbers (only) if configured in APN */
	pdp->tx_gpdu_seq = apn->cfg.tx_gpdu_seq;

	LOGPPDP(LOGL_INFO, pdp, "Successful PDP Context Creation: APN=%s(%s), TEIC=%u, IPv4=%s, IPv6=%s\n",
		name_buf, apn->cfg.name, pdp->teic_own,
		addrv4 ? inet_ntop(AF_INET, &addrv4->addr.v4, straddrv4, sizeof(straddrv4)) : "none",
		addrv6 ? inet_ntop(AF_INET6, &addrv6->addr.v6, straddrv6, sizeof(straddrv6)) : "none");
	gtp_create_context_resp(gsn, pdp, GTPCAUSE_ACC_REQ);
	return 0;		/* Success */

err_pool_full:
	LOGPPDP(LOGL_ERROR, pdp, "Cannot allocate IP address from pool (full!)\n");
	gtp_create_context_resp(gsn, pdp, -rc);
	return 0;	/* Already in use, or no more available */

err_wrong_af:
	LOGPPDP(LOGL_ERROR, pdp, "APN doesn't support requested EUA / AF type\n");
	gtp_create_context_resp(gsn, pdp, GTPCAUSE_UNKNOWN_PDP);
	return 0;
}

static uint16_t inet_checksum(void *data, int len) {

	int nleft = len;
	int sum = 0;
	unsigned short *w = data;
	unsigned short checksum = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1){
		*(unsigned char *)(&checksum) = *(unsigned char *)w;
		sum += checksum;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	checksum = ~sum;
	return (checksum);
}

/* Generate and send an ICMP HOST UNREACHABLE Packet */
static void ipv4_host_unreach(struct tun_t *tun, void *pack, unsigned len)
{
	char send_buf[sizeof(struct ip) + sizeof(struct icmp) + len];
	len = len - 20;
	struct iphdr *iph = (struct iphdr *)pack;

	memset(send_buf, 0, sizeof(send_buf));

	struct ip *ip = (struct ip *)send_buf;
	struct icmp *icmp = (struct icmp *)(ip + 1);

	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_len = htons(sizeof(send_buf));
	ip->ip_id = rand();
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_sum = 0;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_src.s_addr = iph->daddr;
	ip->ip_dst.s_addr = iph->saddr;
	ip->ip_sum = inet_checksum(ip, sizeof(send_buf));

	icmp->icmp_type = ICMP_DEST_UNREACH;
	icmp->icmp_code = ICMP_HOST_UNREACH;
	icmp->icmp_id = 0;
	icmp->icmp_seq = 0;
	icmp->icmp_cksum = 0;

	memcpy(send_buf + sizeof(ip) + sizeof(icmp) + 12, pack, len);
	icmp->icmp_cksum = inet_checksum(icmp, sizeof(icmp) + 12 + len);
	tun_encaps(tun, send_buf, sizeof(send_buf));
}

/* Internet-originated IP packet, needs to be sent via GTP towards MS */
static int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len)
{
	struct apn_ctx *apn = tun->priv;
	struct ippoolm_t *ipm;
	struct in46_addr dst;
	struct iphdr *iph = (struct iphdr *)pack;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	struct ippool_t *pool;
	char straddr[2][INET6_ADDRSTRLEN];
	uint8_t pref_offset;

	switch (iph->version) {
	case 4:
		if (len < sizeof(*iph) || len < 4*iph->ihl)
			return -1;
		dst.len = 4;
		dst.v4.s_addr = iph->daddr;
		pool = apn->v4.pool;
		break;
	case 6:
		/* Due to the fact that 3GPP requires an allocation of a
		 * /64 prefix to each MS, we must instruct
		 * ippool_getip() below to match only the leading /64
		 * prefix, i.e. the first 8 bytes of the address. If the ll addr
		 * is used, then the match should be done on the trailing 64
		 * bits. */
		dst.len = 8;
		pref_offset = IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst) ? 8 : 0;
		memcpy(&dst.v6, ((uint8_t*)&ip6h->ip6_dst) + pref_offset, 8);
		pool = apn->v6.pool;
		break;
	default:
		LOGTUN(LOGL_NOTICE, tun, "non-IPv%u packet received\n", iph->version);
		return -1;
	}

	/* IPv6 packet but no IPv6 pool, or IPv4 packet with no IPv4 pool */
	if (!pool)
		return 0;

	if (ippool_getip(pool, &ipm, &dst)) {
		LOGTUN(LOGL_DEBUG, tun, "APN(%s) Rx DL data packet for IP address outside "
		       "pool of managed addresses: %s <- %s\n",
		       apn->cfg.name,
		       iph->version == 4 ?
		         inet_ntop(AF_INET, &iph->daddr, straddr[0], sizeof(straddr[0])) :
		         inet_ntop(AF_INET6, &ip6h->ip6_dst, straddr[0], sizeof(straddr[0])),
		       iph->version == 4 ?
		         inet_ntop(AF_INET, &iph->saddr, straddr[1], sizeof(straddr[1])) :
		         inet_ntop(AF_INET6, &ip6h->ip6_src, straddr[1], sizeof(straddr[1])));
		return 0;
	}

	if (ipm->peer)	{	/* Check if a peer protocol is defined */
		struct pdp_t *pdp = (struct pdp_t *)ipm->peer;
		LOGTUN(LOGL_DEBUG, tun, "APN(%s) Rx DL data packet for PDP(%s:%u): %s <- %s\n",
		       apn->cfg.name,
		       imsi_gtp2str(&(pdp)->imsi), (pdp)->nsapi,
		       iph->version == 4 ?
		         inet_ntop(AF_INET, &iph->daddr, straddr[0], sizeof(straddr[0])) :
		         inet_ntop(AF_INET6, &ip6h->ip6_dst, straddr[0], sizeof(straddr[0])),
		       iph->version == 4 ?
		         inet_ntop(AF_INET, &iph->saddr, straddr[1], sizeof(straddr[1])) :
		         inet_ntop(AF_INET6, &ip6h->ip6_src, straddr[1], sizeof(straddr[1])));
		gtp_data_req(apn->ggsn->gsn, pdp, pack, len);
	} else {
		LOGTUN(LOGL_DEBUG, tun, "APN(%s) Rx DL data packet for IP address with no "
		       "associated PDP Ctx: %s <- %s\n",
		       apn->cfg.name,
		       iph->version == 4 ?
 		         inet_ntop(AF_INET, &iph->daddr, straddr[0], sizeof(straddr[0])) :
 		         inet_ntop(AF_INET6, &ip6h->ip6_dst, straddr[0], sizeof(straddr[0])),
 		       iph->version == 4 ?
 		         inet_ntop(AF_INET, &iph->saddr, straddr[1], sizeof(straddr[1])) :
 		         inet_ntop(AF_INET6, &ip6h->ip6_src, straddr[1], sizeof(straddr[1])));
		/* TODO: Implement ipv6 */
		if (iph->version != 4)
			return 0;
		ipv4_host_unreach(tun, pack, len);
	}
	return 0;
}

/* MS-originated GTP1-U packet, needs to be sent via TUN device */
static int encaps_tun(struct pdp_t *pdp, void *pack, unsigned len)
{
	struct iphdr *iph = (struct iphdr *)pack;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	struct tun_t *tun = (struct tun_t *)pdp->ipif;
	struct apn_ctx *apn = tun->priv;
	char straddr[INET6_ADDRSTRLEN];
	struct ippoolm_t *peer;
	uint8_t pref_offset;

	OSMO_ASSERT(tun);
	OSMO_ASSERT(apn);

	LOGPPDP(LOGL_DEBUG, pdp, "Packet received on APN(%s): forwarding to tun %s\n", apn->cfg.name, tun->devname);

	switch (iph->version) {
	case 6:
		peer = pdp_get_peer_ipv(pdp, true);
		if (!peer) {
			LOGPPDP(LOGL_ERROR, pdp, "Packet from MS IPv6 with unassigned EUA: %s\n",
				osmo_hexdump(pack, len));
			return -1;
		}

		/* Validate packet comes from IPaddr assigned to the pdp ctx.
		   If packet is a LL addr, then EUA is in the lower 64 bits,
		   otherwise it's used as the 64 prefix */
		pref_offset = IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src) ? 8 : 0;
		if (memcmp(((uint8_t*)&ip6h->ip6_src) + pref_offset, &peer->addr.v6, 8)) {
			LOGPPDP(LOGL_ERROR, pdp, "Packet from MS using unassigned src IPv6: %s\n",
				inet_ntop(AF_INET6, &ip6h->ip6_src, straddr, sizeof(straddr)));
			return -1;
		}

		/* daddr: all-routers multicast addr */
		if (IN6_ARE_ADDR_EQUAL(&ip6h->ip6_dst, &all_router_mcast_addr))
			return handle_router_mcast(pdp->gsn, pdp, &peer->addr.v6,
						&apn->v6_lladdr, pack, len);
		break;
	case 4:
		peer = pdp_get_peer_ipv(pdp, false);
		if (!peer) {
			LOGPPDP(LOGL_ERROR, pdp, "Packet from MS IPv4 with unassigned EUA: %s\n",
				osmo_hexdump(pack, len));
			return -1;
		}

		/* Validate packet comes from IPaddr assigned to the pdp ctx */
		if (memcmp(&iph->saddr, &peer->addr.v4, sizeof(peer->addr.v4))) {
			LOGPPDP(LOGL_ERROR, pdp, "Packet from MS using unassigned src IPv4: %s\n",
				inet_ntop(AF_INET, &iph->saddr, straddr, sizeof(straddr)));
			return -1;
		}
		break;
	default:
		LOGPPDP(LOGL_ERROR, pdp, "Packet from MS is neither IPv4 nor IPv6: %s\n",
			osmo_hexdump(pack, len));
		return -1;
	}
	return tun_encaps((struct tun_t *)pdp->ipif, pack, len);
}

/* callback for tun device osmocom select loop integration */
static int ggsn_tun_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct apn_ctx *apn = fd->data;

	OSMO_ASSERT(what & OSMO_FD_READ);

	return tun_decaps(apn->tun.tun);
}

/* callback for libgtp osmocom select loop integration */
static int ggsn_gtp_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct ggsn_ctx *ggsn = fd->data;
	int rc;

	OSMO_ASSERT(what & OSMO_FD_READ);

	switch (fd->priv_nr) {
	case 0:
		rc = gtp_decaps0(ggsn->gsn);
		break;
	case 1:
		rc = gtp_decaps1c(ggsn->gsn);
		break;
	case 2:
		rc = gtp_decaps1u(ggsn->gsn);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
	return rc;
}

/* libgtp callback for confirmations */
static int cb_conf(int type, int cause, struct pdp_t *pdp, void *cbp)
{
	struct sgsn_peer *sgsn;
	int rc = 0;

	if (cause == EOF)
		LOGP(DGGSN, LOGL_NOTICE, "libgtp EOF (type=%u, pdp=%p, cbp=%p)\n",
			type, pdp, cbp);

	switch (type) {
	case GTP_DELETE_PDP_REQ:
		/* Remark: We actually never reach this path nowadays because
		   only place where we call gtp_delete_context_req2() is during
		   ggsn_close_one_pdp() path, and in that case we free all pdp
		   contexts immediatelly without waiting for confirmation
		   (through gtp_freepdp_teardown()) since we want to tear down
		   the whole APN anyways. As a result, DeleteCtxResponse will
		   never reach here since it will be dropped at some point in
		   lower layers in the Rx path. This code is nevertheless left
		   here in order to ease future developent and avoid possible
		   future memleaks once more scenarios where GGSN sends a
		   DeleteCtxRequest are introduced. */
		if (pdp)
			rc = gtp_freepdp(pdp->gsn, pdp);
		break;
	case GTP_ECHO_REQ:
		sgsn = (struct sgsn_peer *)cbp;
		sgsn_peer_echo_resp(sgsn, cause == EOF);
		break;
	}
	return rc;
}

static int cb_recovery3(struct gsn_t *gsn, struct sockaddr_in *peer, struct pdp_t *pdp, uint8_t recovery)
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *)gsn->priv;
	struct sgsn_peer *sgsn;

	sgsn = ggsn_find_sgsn(ggsn, &peer->sin_addr);
	if (!sgsn) {
		LOGPGGSN(LOGL_NOTICE, ggsn, "Received Recovery IE for unknown SGSN (no PDP contexts active)\n");
		return -EINVAL;
	}

	return sgsn_peer_handle_recovery(sgsn, pdp, recovery);
}

/* Start a given GGSN */
int ggsn_start(struct ggsn_ctx *ggsn)
{
	struct apn_ctx *apn;
	int rc;

	if (ggsn->started)
		return 0;

	LOGPGGSN(LOGL_INFO, ggsn, "Starting GGSN\n");

	/* Start libgtp listener */
	if (gtp_new(&ggsn->gsn, ggsn->cfg.state_dir, &ggsn->cfg.listen_addr.v4, GTP_MODE_GGSN)) {
		LOGPGGSN(LOGL_ERROR, ggsn, "Failed to create GTP: %s\n", strerror(errno));
		return -1;
	}
	ggsn->gsn->priv = ggsn;

	/* patch in different addresses to use (in case we're behind NAT, the listen
	 * address is different from what we advertise externally) */
	if (ggsn->cfg.gtpc_addr.v4.s_addr)
		ggsn->gsn->gsnc = ggsn->cfg.gtpc_addr.v4;

	if (ggsn->cfg.gtpu_addr.v4.s_addr)
		ggsn->gsn->gsnu = ggsn->cfg.gtpu_addr.v4;

	/* Register File Descriptors */
	osmo_fd_setup(&ggsn->gtp_fd0, ggsn->gsn->fd0, OSMO_FD_READ, ggsn_gtp_fd_cb, ggsn, 0);
	rc = osmo_fd_register(&ggsn->gtp_fd0);
	OSMO_ASSERT(rc == 0);

	osmo_fd_setup(&ggsn->gtp_fd1c, ggsn->gsn->fd1c, OSMO_FD_READ, ggsn_gtp_fd_cb, ggsn, 1);
	rc = osmo_fd_register(&ggsn->gtp_fd1c);
	OSMO_ASSERT(rc == 0);

	osmo_fd_setup(&ggsn->gtp_fd1u, ggsn->gsn->fd1u, OSMO_FD_READ, ggsn_gtp_fd_cb, ggsn, 2);
	rc = osmo_fd_register(&ggsn->gtp_fd1u);
	OSMO_ASSERT(rc == 0);

	gtp_set_cb_data_ind(ggsn->gsn, encaps_tun);
	gtp_set_cb_delete_context(ggsn->gsn, delete_context);
	gtp_set_cb_create_context_ind(ggsn->gsn, create_context_ind);
	gtp_set_cb_conf(ggsn->gsn, cb_conf);
	gtp_set_cb_recovery3(ggsn->gsn, cb_recovery3);

	LOGPGGSN(LOGL_NOTICE, ggsn, "Successfully started\n");
	ggsn->started = true;

	llist_for_each_entry(apn, &ggsn->apn_list, list)
		apn_start(apn);

	return 0;
}

/* Stop a given GGSN */
int ggsn_stop(struct ggsn_ctx *ggsn)
{
	struct apn_ctx *apn;

	if (!ggsn->started)
		return 0;

	/* iterate over all APNs and stop them */
	llist_for_each_entry(apn, &ggsn->apn_list, list)
		apn_stop(apn);

	osmo_fd_unregister(&ggsn->gtp_fd1u);
	osmo_fd_unregister(&ggsn->gtp_fd1c);
	osmo_fd_unregister(&ggsn->gtp_fd0);

	if (ggsn->gsn) {
		gtp_free(ggsn->gsn);
		ggsn->gsn = NULL;
	}

	ggsn->started = false;
	return 0;
}
