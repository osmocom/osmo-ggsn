#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>

#include "../lib/tun.h"
#include "../lib/ippool.h"
#include "../lib/syserr.h"
#include "../lib/in46_addr.h"
#include "../gtp/gtp.h"

#define APN_TYPE_IPv4	0x01	/* v4-only */
#define APN_TYPE_IPv6	0x02	/* v6-only */
#define APN_TYPE_IPv4v6	0x04	/* v4v6 dual-stack */

struct ggsn_ctx;

struct apn_ctx_ip {
	struct {
		struct in46_prefix ifconfig_prefix;
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
		/* administratively shut-down (true) or not (false) */
		bool shutdown;
	} cfg;

	/* corresponding tun device */
	struct {
		struct {
			/* name of the network device */
			char *dev_name;
			/* ip-up and ip-down script names/paths */
			char *ipup_script;
			char *ipdown_script;
		} cfg;
		struct tun_t *tun;
		struct osmo_fd fd;
	} tun;

	/* ipv6 link-local address */
	struct in6_addr v6_lladdr;

	struct apn_ctx_ip v4;
	struct apn_ctx_ip v6;
};

struct ggsn_ctx {
	/* global list of GGSNs */
	struct llist_head list;

	/* list of APNs in this GGSN */
	struct llist_head apn_list;

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
		/* administratively shut-down (true) or not (false) */
		bool shutdown;
	} cfg;

	/* The libgtp (G)GSN instance, i.e. what listens to GTP */
	struct gsn_t *gsn;

	/* osmo-fd for gsn */
	struct osmo_fd gtp_fd0;
	struct osmo_fd gtp_fd1c;
	struct osmo_fd gtp_fd1u;

	struct osmo_timer_list gtp_timer;
};

/* ggsn_vty.c */
extern struct llist_head g_ggsn_list;
extern struct vty_app_info g_vty_info;
extern int ggsn_vty_init(void);
struct ggsn_ctx *ggsn_find(const char *name);
struct ggsn_ctx *ggsn_find_or_create(void *ctx, const char *name);
struct apn_ctx *ggsn_find_apn(struct ggsn_ctx *ggsn, const char *name);
struct apn_ctx *ggsn_find_or_create_apn(struct ggsn_ctx *ggsn, const char *name);

/* ggsn.c */
extern void *tall_ggsn_ctx;
extern int ggsn_start(struct ggsn_ctx *ggsn);
extern int ggsn_stop(struct ggsn_ctx *ggsn);
extern int apn_start(struct apn_ctx *apn);
extern int apn_stop(struct apn_ctx *apn, bool force);
