/*
 * OsmoGGSN - Gateway GPRS Support Node
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 * Copyright (C) 2017 by Harald Welte <laforge@gnumonks.org>
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
#include <netinet/ip6.h>

#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/timer.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/command.h>
#include <osmocom/gsm/apn.h>

#include "../lib/tun.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "../lib/in46_addr.h"
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "gtp-kernel.h"
#include "icmpv6.h"
#include "ggsn.h"

void *tall_ggsn_ctx;

static int end = 0;
static int daemonize = 0;
static struct ctrl_handle *g_ctrlh;

struct ul255_t qos;
struct ul255_t apn;

#define LOGPAPN(level, apn, fmt, args...)			\
	LOGP(DGGSN, level, "APN(%s): " fmt, (apn)->cfg.name, ## args)

#define LOGPGGSN(level, ggsn, fmt, args...)			\
	LOGP(DGGSN, level, "GGSN(%s): " fmt, (ggsn)->cfg.name, ## args)

#define LOGPPDP(level, pdp, fmt, args...) LOGPDPX(DGGSN, level, pdp, fmt, ## args)

static int ggsn_tun_fd_cb(struct osmo_fd *fd, unsigned int what);
static int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len);


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
		LOGPPDP(LOGL_DEBUG, pdp, "Sending DELETE PDP CTX due to shutdown\n");
		gtp_delete_context_req(pdp->gsn, pdp, NULL, 1);
	}
}

int apn_stop(struct apn_ctx *apn, bool force)
{
	LOGPAPN(LOGL_NOTICE, apn, "%sStopping\n", force ? "FORCED " : "");
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
		/* release tun device */
		LOGPAPN(LOGL_INFO, apn, "Closing TUN device %s\n", apn->tun.tun->devname);
		osmo_fd_unregister(&apn->tun.fd);
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

	if (apn->started)
		return 0;

	LOGPAPN(LOGL_INFO, apn, "Starting\n");
	switch (apn->cfg.gtpu_mode) {
	case APN_GTPU_MODE_TUN:
		LOGPAPN(LOGL_INFO, apn, "Opening TUN device %s\n", apn->tun.cfg.dev_name);
		if (tun_new(&apn->tun.tun, apn->tun.cfg.dev_name)) {
			LOGPAPN(LOGL_ERROR, apn, "Failed to configure tun device\n");
			return -1;
		}
		LOGPAPN(LOGL_INFO, apn, "Opened TUN device %s\n", apn->tun.tun->devname);

		/* Register with libosmcoore */
		osmo_fd_setup(&apn->tun.fd, apn->tun.tun->fd, BSC_FD_READ, ggsn_tun_fd_cb, apn, 0);
		osmo_fd_register(&apn->tun.fd);

		/* Set TUN library callback */
		tun_set_cb_ind(apn->tun.tun, cb_tun_ind);

		if (apn->v4.cfg.ifconfig_prefix.addr.len) {
			LOGPAPN(LOGL_INFO, apn, "Setting tun IP address %s\n",
				in46p_ntoa(&apn->v4.cfg.ifconfig_prefix));
			if (tun_setaddr(apn->tun.tun, &apn->v4.cfg.ifconfig_prefix.addr, NULL,
					apn->v4.cfg.ifconfig_prefix.prefixlen)) {
				LOGPAPN(LOGL_ERROR, apn, "Failed to set tun IPv4 address %s: %s\n",
					in46p_ntoa(&apn->v4.cfg.ifconfig_prefix), strerror(errno));
				apn_stop(apn, false);
				return -1;
			}
		}

		if (apn->v6.cfg.ifconfig_prefix.addr.len) {
			LOGPAPN(LOGL_INFO, apn, "Setting tun IPv6 address %s\n",
				in46p_ntoa(&apn->v6.cfg.ifconfig_prefix));
			if (tun_setaddr(apn->tun.tun, &apn->v6.cfg.ifconfig_prefix.addr, NULL,
					apn->v6.cfg.ifconfig_prefix.prefixlen)) {
				LOGPAPN(LOGL_ERROR, apn, "Failed to set tun IPv6 address %s: %s. "
					"Ensure you have ipv6 support and not used the disable_ipv6 sysctl?\n",
					in46p_ntoa(&apn->v6.cfg.ifconfig_prefix), strerror(errno));
				apn_stop(apn, false);
				return -1;
			}
		}

		if (apn->tun.cfg.ipup_script) {
			LOGPAPN(LOGL_INFO, apn, "Running ip-up script %s\n",
				apn->tun.cfg.ipup_script);
			tun_runscript(apn->tun.tun, apn->tun.cfg.ipup_script);
		}

		if (apn->cfg.apn_type_mask & (APN_TYPE_IPv6|APN_TYPE_IPv4v6)) {
			if (tun_ip_local_get(apn->tun.tun, &ipv6_tun_linklocal_ip, 1, IP_TYPE_IPv6_LINK) < 1) {
				LOGPAPN(LOGL_ERROR, apn, "Cannot obtain IPv6 link-local address of "
					"interface: %s\n", strerror(errno));
				apn_stop(apn, false);
				return -1;
			}
			apn->v6_lladdr = ipv6_tun_linklocal_ip.addr.v6;
		}

		/* set back-pointer from TUN device to APN */
		apn->tun.tun->priv = apn;
		break;
	case APN_GTPU_MODE_KERNEL_GTP:
		if (apn->cfg.apn_type_mask & (APN_TYPE_IPv6|APN_TYPE_IPv4v6)) {
			LOGPAPN(LOGL_ERROR, apn, "Kernel GTP currently supports only IPv4\n");
			apn_stop(apn, false);
			return -1;
		}
		LOGPAPN(LOGL_ERROR, apn, "Setting up Kernel GTP\n");
		/* use GTP kernel module for data packet encapsulation */
		if (gtp_kernel_init(apn->ggsn->gsn, apn->tun.cfg.dev_name,
				    &apn->v4.cfg.ifconfig_prefix, apn->tun.cfg.ipup_script) < 0) {
			return -1;
		}
		break;
	default:
		LOGPAPN(LOGL_ERROR, apn, "Unknown GTPU Mode %d\n", apn->cfg.gtpu_mode);
		return -1;
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
			apn_stop(apn, false);
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
			apn_stop(apn, false);
			return -1;
		}
		talloc_free(blacklist);
	}

	LOGPAPN(LOGL_NOTICE, apn, "Successfully started\n");
	apn->started = true;
	return 0;
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
	struct ippoolm_t *ipp = (struct ippoolm_t *)pdp->peer;
	struct apn_ctx *apn = pdp->priv;

	LOGPPDP(LOGL_INFO, pdp, "Deleting PDP context\n");
	struct ippoolm_t *member = pdp->peer;

	if (pdp->peer) {
		send_trap(gsn, pdp, member, "imsi-rem-ip"); /* TRAP with IP removal */
		ippool_freeip(ipp->pool, ipp);
	} else
		LOGPPDP(LOGL_ERROR, pdp, "Cannot find/free IP Pool member\n");

	if (gtp_kernel_tunnel_del(pdp, apn->tun.cfg.dev_name)) {
		LOGPPDP(LOGL_ERROR, pdp, "Cannot delete tunnel from kernel:%s\n",
			strerror(errno));
	}

	return 0;
}

#include <osmocom/gsm/tlv.h>

/* 3GPP TS 24.008 10.6.5.3 */
enum pco_protocols {
	PCO_P_LCP		= 0xC021,
	PCO_P_PAP		= 0xC023,
	PCO_P_CHAP		= 0xC223,
	PCO_P_IPCP		= 0x8021,
	PCO_P_PCSCF_ADDR	= 0x0001,
	PCO_P_IM_CN_SS_F	= 0x0002,
	PCO_P_DNS_IPv6_ADDR	= 0x0003,
	PCO_P_POLICY_CTRL_REJ	= 0x0004,	/* only in Network->MS */
	PCO_P_MS_SUP_NETREQ_BCI	= 0x0005,
	/* reserved */
	PCO_P_DSMIPv6_HA_ADDR	= 0x0007,
	PCO_P_DSMIPv6_HN_PREF	= 0x0008,
	PCO_P_DSMIPv6_v4_HA_ADDR= 0x0009,
	PCO_P_IP_ADDR_VIA_NAS	= 0x000a,	/* only MS->Network */
	PCO_P_IPv4_ADDR_VIA_DHCP= 0x000b,	/* only MS->Netowrk */
	PCO_P_PCSCF_IPv4_ADDR	= 0x000c,
	PCO_P_DNS_IPv4_ADDR	= 0x000d,
	PCO_P_MSISDN		= 0x000e,
	PCO_P_IFOM_SUPPORT	= 0x000f,
	PCO_P_IPv4_LINK_MTU	= 0x0010,
	PCO_P_MS_SUPP_LOC_A_TFT	= 0x0011,
	PCO_P_PCSCF_RESEL_SUP	= 0x0012,	/* only MS->Network */
	PCO_P_NBIFOM_REQ	= 0x0013,
	PCO_P_NBIFOM_MODE	= 0x0014,
	PCO_P_NONIP_LINK_MTU	= 0x0015,
	PCO_P_APN_RATE_CTRL_SUP	= 0x0016,
	PCO_P_PS_DATA_OFF_UE	= 0x0017,
	PCO_P_REL_DATA_SVC	= 0x0018,
};

/* determine if PCO contains given protocol */
static bool pco_contains_proto(struct ul255_t *pco, uint16_t prot)
{
	uint8_t *cur = pco->v + 1;

	/* iterate over PCO and check if protocol contained */
	while (cur + 3 <= pco->v + pco->l) {
		uint16_t cur_prot = osmo_load16be(cur);
		uint8_t cur_len = cur[2];
		if (cur_prot == prot)
			return true;
		if (cur_len == 0)
			break;
		cur += cur_len + 3;
	}
	return false;
}

/* determine if PDP context has IPv6 support */
static bool pdp_has_v4(struct pdp_t *pdp)
{
	if (pdp->eua.l == 4+2)
		return true;
	else
		return false;
}

/* construct an IPCP PCO from up to two given DNS addreses */
static int build_ipcp_pco(struct msgb *msg, uint8_t id, const struct in46_addr *dns1,
			  const struct in46_addr *dns2)
{
	uint8_t *len1, *len2;
	uint8_t *start = msg->tail;
	unsigned int len_appended;

	/* Three byte T16L header */
	msgb_put_u16(msg, 0x8021);	/* IPCP */
	len1 = msgb_put(msg, 1);	/* Length of contents: delay */

	msgb_put_u8(msg, 0x02);		/* ACK */
	msgb_put_u8(msg, id);		/* ID: Needs to match request */
	msgb_put_u8(msg, 0x00);		/* Length MSB */
	len2 = msgb_put(msg, 1);	/* Length LSB: delay */

	if (dns1 && dns1->len == 4) {
		msgb_put_u8(msg, 0x81);		/* DNS1 Tag */
		msgb_put_u8(msg, 2 + dns1->len);/* DNS1 Length, incl. TL */
		msgb_put_u32(msg, dns1->v4.s_addr);
	}

	if (dns2 && dns2->len == 4) {
		msgb_put_u8(msg, 0x83);		/* DNS2 Tag */
		msgb_put_u8(msg, 2 + dns2->len);/* DNS2 Length, incl. TL */
		msgb_put_u32(msg, dns2->v4.s_addr);
	}

	/* patch in length values */
	len_appended = msg->tail - start;
	*len1 = len_appended - 3;
	*len2 = len_appended - 3;

	return 0;
}

/* process one PCO request from a MS/UE, putting together the proper responses */
static void process_pco(struct apn_ctx *apn, struct pdp_t *pdp)
{
	struct msgb *msg = msgb_alloc(256, "PCO");
	unsigned int i;

	OSMO_ASSERT(msg);
	msgb_put_u8(msg, 0x80); /* ext-bit + configuration protocol byte */

	/* FIXME: also check if primary / secondary DNS was requested */
	if (pdp_has_v4(pdp) && pco_contains_proto(&pdp->pco_req, PCO_P_IPCP)) {
		/* FIXME: properly implement this for IPCP */
		build_ipcp_pco(msg, 0, &apn->v4.cfg.dns[0], &apn->v4.cfg.dns[1]);
	}

	if (pco_contains_proto(&pdp->pco_req, PCO_P_DNS_IPv6_ADDR)) {
		for (i = 0; i < ARRAY_SIZE(apn->v6.cfg.dns); i++) {
			struct in46_addr *i46a = &apn->v6.cfg.dns[i];
			if (i46a->len != 16)
				continue;
			msgb_t16lv_put(msg, PCO_P_DNS_IPv6_ADDR, i46a->len, i46a->v6.s6_addr);
		}
	}

	if (pco_contains_proto(&pdp->pco_req, PCO_P_DNS_IPv4_ADDR)) {
		for (i = 0; i < ARRAY_SIZE(apn->v4.cfg.dns); i++) {
			struct in46_addr *i46a = &apn->v4.cfg.dns[i];
			if (i46a->len != 4)
				continue;
			msgb_t16lv_put(msg, PCO_P_DNS_IPv4_ADDR, i46a->len, (uint8_t *)&i46a->v4);
		}
	}

	if (msgb_length(msg) > 1) {
		memcpy(pdp->pco_neg.v, msgb_data(msg), msgb_length(msg));
		pdp->pco_neg.l = msgb_length(msg);
	} else
		pdp->pco_neg.l = 0;

	msgb_free(msg);
}

static bool apn_supports_ipv4(const struct apn_ctx *apn)
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

int create_context_ind(struct pdp_t *pdp)
{
	static char name_buf[256];
	struct gsn_t *gsn = pdp->gsn;
	struct ggsn_ctx *ggsn = gsn->priv;
	struct in46_addr addr;
	struct ippoolm_t *member;
	struct apn_ctx *apn;
	int rc;

	osmo_apn_to_str(name_buf, pdp->apn_req.v, pdp->apn_req.l);

	LOGPPDP(LOGL_DEBUG, pdp, "Processing create PDP context request for APN '%s'\n", name_buf);

	/* First find an exact APN name match */
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

	/* FIXME: we manually force all context requests to dynamic here! */
	if (pdp->eua.l > 2)
		pdp->eua.l = 2;

	memcpy(pdp->qos_neg0, pdp->qos_req0, sizeof(pdp->qos_req0));

	memcpy(pdp->qos_neg.v, pdp->qos_req.v, pdp->qos_req.l);	/* TODO */
	pdp->qos_neg.l = pdp->qos_req.l;

	if (in46a_from_eua(&pdp->eua, &addr)) {
		LOGPPDP(LOGL_ERROR, pdp, "Cannot decode EUA from MS/SGSN: %s\n",
			osmo_hexdump(pdp->eua.v, pdp->eua.l));
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_UNKNOWN_PDP);
		return 0;
	}

	if (addr.len == sizeof(struct in_addr)) {
		/* does this APN actually have an IPv4 pool? */
		if (!apn_supports_ipv4(apn))
			goto err_wrong_af;

		rc = ippool_newip(apn->v4.pool, &member, &addr, 0);
		if (rc < 0)
			goto err_pool_full;
		in46a_to_eua(&member->addr, &pdp->eua);

		/* TODO: In IPv6, EUA doesn't contain the actual IP addr/prefix! */
		if (gtp_kernel_tunnel_add(pdp, apn->tun.cfg.dev_name) < 0) {
			LOGPPDP(LOGL_ERROR, pdp, "Cannot add tunnel to kernel: %s\n", strerror(errno));
			gtp_create_context_resp(gsn, pdp, GTPCAUSE_SYS_FAIL);
			return 0;
		}
	} else if (addr.len == sizeof(struct in6_addr)) {
		struct in46_addr tmp;

		/* does this APN actually have an IPv6 pool? */
		if (!apn_supports_ipv6(apn))
			goto err_wrong_af;

		rc = ippool_newip(apn->v6.pool, &member, &addr, 0);
		if (rc < 0)
			goto err_pool_full;

		/* IPv6 doesn't really send the real/allocated address at this point, but just
		 * the link-identifier which the MS shall use for router solicitation */
		tmp.len = addr.len;
		/* initialize upper 64 bits to prefix, they are discarded by MS anyway */
		memcpy(tmp.v6.s6_addr, &member->addr.v6, 8);
		/* use allocated 64bit prefix as lower 64bit, used as link id by MS */
		memcpy(tmp.v6.s6_addr+8, &member->addr.v6, 8);
		in46a_to_eua(&tmp, &pdp->eua);
	} else
		OSMO_ASSERT(0);

	pdp->peer = member;
	pdp->ipif = apn->tun.tun;	/* TODO */
	pdp->priv = apn;
	member->peer = pdp;

	if (!send_trap(gsn, pdp, member, "imsi-ass-ip")) { /* TRAP with IP assignment */
		gtp_create_context_resp(gsn, pdp, GTPCAUSE_NO_RESOURCES);
		return 0;
	}

	process_pco(apn, pdp);

	/* Transmit G-PDU sequence numbers (only) if configured in APN */
	pdp->tx_gpdu_seq = apn->cfg.tx_gpdu_seq;

	LOGPPDP(LOGL_INFO, pdp, "Successful PDP Context Creation: APN=%s(%s), TEIC=%u, IP=%s\n",
		name_buf, apn->cfg.name, pdp->teic_own, in46a_ntoa(&member->addr));
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

/* Internet-originated IP packet, needs to be sent via GTP towards MS */
static int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len)
{
	struct apn_ctx *apn = tun->priv;
	struct ippoolm_t *ipm;
	struct in46_addr dst;
	struct iphdr *iph = (struct iphdr *)pack;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	struct ippool_t *pool;

	if (iph->version == 4) {
		if (len < sizeof(*iph) || len < 4*iph->ihl)
			return -1;
		dst.len = 4;
		dst.v4.s_addr = iph->daddr;
		pool = apn->v4.pool;
	} else if (iph->version == 6) {
		/* Due to the fact that 3GPP requires an allocation of a
		 * /64 prefix to each MS, we must instruct
		 * ippool_getip() below to match only the leading /64
		 * prefix, i.e. the first 8 bytes of the address */
		dst.len = 8;
		dst.v6 = ip6h->ip6_dst;
		pool = apn->v6.pool;
	} else {
		LOGP(DTUN, LOGL_NOTICE, "non-IPv packet received from tun\n");
		return -1;
	}

	/* IPv6 packet but no IPv6 pool, or IPv4 packet with no IPv4 pool */
	if (!pool)
		return 0;

	DEBUGP(DTUN, "Received packet from tun!\n");

	if (ippool_getip(pool, &ipm, &dst)) {
		DEBUGP(DTUN, "Received packet with no PDP contex!!\n");
		return 0;
	}

	if (ipm->peer)		/* Check if a peer protocol is defined */
		gtp_data_req(apn->ggsn->gsn, (struct pdp_t *)ipm->peer, pack, len);
	return 0;
}

/* RFC3307 link-local scope multicast address */
static const struct in6_addr all_router_mcast_addr = {
	.s6_addr = { 0xff,0x02,0,0,  0,0,0,0, 0,0,0,0,  0,0,0,2 }
};

/* MS-originated GTP1-U packet, needs to be sent via TUN device */
static int encaps_tun(struct pdp_t *pdp, void *pack, unsigned len)
{
	struct iphdr *iph = (struct iphdr *)pack;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	struct tun_t *tun = (struct tun_t *)pdp->ipif;
	struct apn_ctx *apn = tun->priv;

	OSMO_ASSERT(tun);
	OSMO_ASSERT(apn);

	LOGPPDP(LOGL_DEBUG, pdp, "Packet received: forwarding to tun\n");

	switch (iph->version) {
	case 6:
		/* daddr: all-routers multicast addr */
		if (IN6_ARE_ADDR_EQUAL(&ip6h->ip6_dst, &all_router_mcast_addr))
			return handle_router_mcast(pdp->gsn, pdp, &apn->v6_lladdr, pack, len);
		break;
	case 4:
		break;
	default:
		LOGPPDP(LOGL_ERROR, pdp, "Packet from MS is neither IPv4 nor IPv6: %s\n",
			osmo_hexdump(pack, len));
		return -1;
	}
	return tun_encaps((struct tun_t *)pdp->ipif, pack, len);
}

static char *config_file = "osmo-ggsn.cfg";

/* callback for tun device osmocom select loop integration */
static int ggsn_tun_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct apn_ctx *apn = fd->data;

	OSMO_ASSERT(what & BSC_FD_READ);

	return tun_decaps(apn->tun.tun);
}

/* callback for libgtp osmocom select loop integration */
static int ggsn_gtp_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct ggsn_ctx *ggsn = fd->data;
	int rc;

	OSMO_ASSERT(what & BSC_FD_READ);

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

static void ggsn_gtp_tmr_start(struct ggsn_ctx *ggsn)
{
	struct timeval next;

	/* Retrieve next retransmission as timeval */
	gtp_retranstimeout(ggsn->gsn, &next);

	/* re-schedule the timer */
	osmo_timer_schedule(&ggsn->gtp_timer, next.tv_sec, next.tv_usec/1000);
}

/* timer callback for libgtp retransmission and ping */
static void ggsn_gtp_tmr_cb(void *data)
{
	struct ggsn_ctx *ggsn = data;

	/* do all the retransmissions as needed */
	gtp_retrans(ggsn->gsn);

	ggsn_gtp_tmr_start(ggsn);
}

/* To exit gracefully. Used with GCC compilation flag -pg and gprof */
static void signal_handler(int s)
{
	LOGP(DGGSN, LOGL_NOTICE, "signal %d received\n", s);
	switch (s) {
	case SIGINT:
	case SIGTERM:
		LOGP(DGGSN, LOGL_NOTICE, "SIGINT received, shutting down\n");
		end = 1;
		break;
	case SIGABRT:
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_ggsn_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
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
	osmo_fd_setup(&ggsn->gtp_fd0, ggsn->gsn->fd0, BSC_FD_READ, ggsn_gtp_fd_cb, ggsn, 0);
	rc = osmo_fd_register(&ggsn->gtp_fd0);
	OSMO_ASSERT(rc == 0);

	osmo_fd_setup(&ggsn->gtp_fd1c, ggsn->gsn->fd1c, BSC_FD_READ, ggsn_gtp_fd_cb, ggsn, 1);
	rc = osmo_fd_register(&ggsn->gtp_fd1c);
	OSMO_ASSERT(rc == 0);

	osmo_fd_setup(&ggsn->gtp_fd1u, ggsn->gsn->fd1u, BSC_FD_READ, ggsn_gtp_fd_cb, ggsn, 2);
	rc = osmo_fd_register(&ggsn->gtp_fd1u);
	OSMO_ASSERT(rc == 0);

	/* Start GTP re-transmission timer */
	osmo_timer_setup(&ggsn->gtp_timer, ggsn_gtp_tmr_cb, ggsn);

	gtp_set_cb_data_ind(ggsn->gsn, encaps_tun);
	gtp_set_cb_delete_context(ggsn->gsn, delete_context);
	gtp_set_cb_create_context_ind(ggsn->gsn, create_context_ind);

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
		apn_stop(apn, true);

	osmo_timer_del(&ggsn->gtp_timer);

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

static void print_usage()
{
	printf("Usage: osmo-ggsn [-h] [-D] [-c configfile] [-V]\n");
}

static void print_help()
{
	printf(	"  Some useful help...\n"
		"  -h --help		This help text\n"
		"  -D --daemonize	Fork the process into a background daemon\n"
		"  -c --config-file	filename The config file to use\n"
		"  -V --version		Print the version of OsmoGGSN\n"
		);
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "version", 0, 0, 'V' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hdc:V", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'D':
			daemonize = 1;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		}
	}
}

int main(int argc, char **argv)
{
	struct ggsn_ctx *ggsn;
	int rc;

	tall_ggsn_ctx = talloc_named_const(NULL, 0, "OsmoGGSN");
	msgb_talloc_ctx_init(tall_ggsn_ctx, 0);

	/* Handle keyboard interrupt SIGINT */
	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);

	osmo_init_ignore_signals();
	osmo_init_logging(&log_info);
	osmo_stats_init(tall_ggsn_ctx);

	vty_init(&g_vty_info);
	logging_vty_add_cmds(NULL);
	osmo_stats_vty_add_cmds(&log_info);
	ggsn_vty_init();
	ctrl_vty_init(tall_ggsn_ctx);

	handle_options(argc, argv);

	rate_ctr_init(tall_ggsn_ctx);

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to open config file: '%s'\n", config_file);
		exit(2);
	}

	rc = telnet_init_dynif(tall_ggsn_ctx, NULL, vty_get_bind_addr(), OSMO_VTY_PORT_GGSN);
	if (rc < 0)
		exit(1);

	g_ctrlh = ctrl_interface_setup(NULL, OSMO_CTRL_PORT_GGSN, NULL);
	if (!g_ctrlh) {
		LOGP(DGGSN, LOGL_ERROR, "Failed to create CTRL interface.\n");
		exit(1);
	}

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

#if 0
	/* qos                                                             */
	qos.l = 3;
	qos.v[2] = (args_info.qos_arg) & 0xff;
	qos.v[1] = ((args_info.qos_arg) >> 8) & 0xff;
	qos.v[0] = ((args_info.qos_arg) >> 16) & 0xff;
#endif

	/* Main select loop */
	while (!end) {
		osmo_select_main(0);
	}

	llist_for_each_entry(ggsn, &g_ggsn_list, list)
		ggsn_stop(ggsn);

	return 1;
}
