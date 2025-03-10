#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/tdef.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/gtp/gtp.h>

#include "../lib/tun.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "../lib/in46_addr.h"

#include "sgsn.h"

#define APN_TYPE_IPv4	0x01	/* v4-only */
#define APN_TYPE_IPv6	0x02	/* v6-only */
#define APN_TYPE_IPv4v6	0x04	/* v4v6 dual-stack */

/* The maximum sane MTU over GTP-U somebody may wish to configure:
 * 9000 bytes aka jumbo frames. */
#define MAX_POSSIBLE_APN_MTU 9000

/* See 3GPP TS 23.060 Annex C: */
#define ETHERNET_MTU      1500
#define IPV4_HDR_MAX_SIZE 60
#define IPV6_HDR_MAX_SIZE 40 /* Assume no extension headers in general... */
#define UDP_HDR_MAX_SIZE  8
#define GTPU_HDR_MAX_SIZE 12 /* Assume no extension headers in general... */
#define MAX_DESIRED_APN_MTU ((ETHERNET_MTU) - (GTPU_HDR_MAX_SIZE) - (UDP_HDR_MAX_SIZE) - (IPV4_HDR_MAX_SIZE))
/* MAX_DESIRED_APN_MTU = 1500 - 60 - 8 - 12 = 1500 - 80 = 1420 */

struct ggsn_ctx;

struct apn_ctx_ip {
	struct {
		struct in46_prefix ifconfig_prefix;
		struct in46_prefix ll_prefix;
		struct in46_prefix static_prefix;
		struct in46_prefix dynamic_prefix;
		/* v4 DNS server names */
		struct in46_addr dns[2];
	} cfg;

	/* v4 address pool */
	struct ippool_t *pool;
};

struct apn_name {
	struct llist_head list;
	char *name;
};

enum apn_gtpu_mode {
	APN_GTPU_MODE_TUN = 0,		/* default */
	APN_GTPU_MODE_KERNEL_GTP,
};

struct apn_ctx {
	/* list of APNs inside GGSN */
	struct llist_head list;
	/* back-pointer to GGSN */
	struct ggsn_ctx *ggsn;

	bool started;

	struct {
		/* Primary name */
		char *name;
		/* Description string */
		char *description;
		/* List of secondary APN names */
		struct llist_head name_list;
		/* types supported address types on this APN */
		uint32_t apn_type_mask;
		/* GTP-U via TUN device or in Linux kernel */
		enum apn_gtpu_mode gtpu_mode;
		/* administratively shut down (true) or not (false) */
		bool shutdown;
		/* transmit G-PDU sequence numbers (true) or not (false) */
		bool tx_gpdu_seq;
		/* MTU announced to the UE */
		uint16_t mtu;
	} cfg;

	/* corresponding tun device */
	struct {
		struct {
			/* name of the network device */
			char *dev_name;
			/* ip-up and ip-down script names/paths */
			char *ipup_script;
			char *ipdown_script;
			/* Whether to apply the MTU (apn->cfg.mtu) on the tun device: */
			bool mtu_apply;
		} cfg;
		struct tun_t *tun;
	} tun;

	/* ipv6 link-local address */
	struct in6_addr v6_lladdr;

	struct apn_ctx_ip v4;
	struct apn_ctx_ip v6;
};

struct pdp_priv_t {
	struct pdp_t *lib; /* pointer to libgtp associated pdp_t instance */
	struct sgsn_peer *sgsn;
	struct apn_ctx *apn;
	struct llist_head entry; /* to be included into sgsn_peer */
	/* struct ggsn_ctx can be reached through lib->gsn->priv, or through sgsn->ggsn */
};

struct ggsn_ctx {
	/* global list of GGSNs */
	struct llist_head list;

	/* list of APNs in this GGSN */
	struct llist_head apn_list;

	/* list of SGSN peers (struct sgsn_peer) in this GGSN. TODO: hash table with key <ip+port>? */
	struct llist_head sgsn_list;

	bool started;

	struct {
		char *name;
		/* Description string */
		char *description;
		/* an APN that shall be used as default for any non-matching APN */
		struct apn_ctx *default_apn;
		/* ADdress to which we listen for GTP */
		struct in46_addr listen_addr;
		/* Local GTP-C address advertised in GTP */
		struct in46_addr gtpc_addr;
		/* Local GTP-U address advertised in GTP */
		struct in46_addr gtpu_addr;
		/* directory for state file */
		char *state_dir;
		/* Time between Echo requests on each SGSN */
		unsigned int echo_interval;
		/* administratively shut down (true) or not (false) */
		bool shutdown;
	} cfg;

	/* The libgtp (G)GSN instance, i.e. what listens to GTP */
	struct gsn_t *gsn;

	/* osmo-fd for gsn */
	struct osmo_fd gtp_fd0;
	struct osmo_fd gtp_fd1c;
	struct osmo_fd gtp_fd1u;
};

/* ggsn_vty.c */
extern struct llist_head g_ggsn_list;
extern struct vty_app_info g_vty_info;
extern int ggsn_vty_init(void);
struct ggsn_ctx *ggsn_find(const char *name);
struct ggsn_ctx *ggsn_find_or_create(void *ctx, const char *name);
struct apn_ctx *ggsn_find_apn(struct ggsn_ctx *ggsn, const char *name);
struct apn_ctx *ggsn_find_or_create_apn(struct ggsn_ctx *ggsn, const char *name);

/* ggsn_main.c */
extern struct ctrl_handle *g_ctrlh;
extern void *tall_ggsn_ctx;
extern struct osmo_tdef_group ggsn_tdef_group[];

/* ggsn.c */
extern int ggsn_start(struct ggsn_ctx *ggsn);
extern int ggsn_stop(struct ggsn_ctx *ggsn);
extern int apn_start(struct apn_ctx *apn);
extern int apn_stop(struct apn_ctx *apn);
void ggsn_close_one_pdp(struct pdp_t *pdp);

#define LOGPAPN(level, apn, fmt, args...)			\
	LOGP(DGGSN, level, "APN(%s): " fmt, (apn)->cfg.name, ## args)

#define LOGPGGSN(level, ggsn, fmt, args...)			\
	LOGP(DGGSN, level, "GGSN(%s): " fmt, (ggsn)->cfg.name, ## args)

#define LOGPPDP(level, pdp, fmt, args...) LOGPDPX(DGGSN, level, pdp, fmt, ## args)
