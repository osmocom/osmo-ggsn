/*
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

#include "../gtp/gtp.h"
#include "../gtp/pdp.h"

#include "ggsn.h"

#define PREFIX_STR	"Prefix (Network/Netmask)\n"
#define IFCONFIG_STR	"GGSN-based interface configuration\n"
#define GGSN_STR	"Gateway GPRS Support NODE (GGSN)\n"

LLIST_HEAD(g_ggsn_list);

enum ggsn_vty_node {
	GGSN_NODE = _LAST_OSMOVTY_NODE + 1,
	APN_NODE,
};

struct ggsn_ctx *ggsn_find(const char *name)
{
	struct ggsn_ctx *ggsn;

	llist_for_each_entry(ggsn, &g_ggsn_list, list) {
		if (!strcmp(ggsn->cfg.name, name))
			return ggsn;
	}
	return NULL;
}

struct ggsn_ctx *ggsn_find_or_create(void *ctx, const char *name)
{
	struct ggsn_ctx *ggsn;

	ggsn = ggsn_find(name);
	if (ggsn)
		return ggsn;

	ggsn = talloc_zero(ctx, struct ggsn_ctx);
	if (!ggsn)
		return NULL;

	ggsn->cfg.name = talloc_strdup(ggsn, name);
	ggsn->cfg.state_dir = talloc_strdup(ggsn, "/tmp");
	ggsn->cfg.shutdown = true;
	INIT_LLIST_HEAD(&ggsn->apn_list);

	llist_add_tail(&ggsn->list, &g_ggsn_list);
	return ggsn;
}

struct apn_ctx *ggsn_find_apn(struct ggsn_ctx *ggsn, const char *name)
{
	struct apn_ctx *apn;

	llist_for_each_entry(apn, &ggsn->apn_list, list) {
		if (!strcmp(apn->cfg.name, name))
			return apn;
	}
	return NULL;
}

struct apn_ctx *ggsn_find_or_create_apn(struct ggsn_ctx *ggsn, const char *name)
{
	struct apn_ctx *apn = ggsn_find_apn(ggsn, name);
	if (apn)
		return apn;

	apn = talloc_zero(ggsn, struct apn_ctx);
	if (!apn)
		return NULL;
	apn->ggsn = ggsn;
	apn->cfg.name = talloc_strdup(apn, name);
	apn->cfg.shutdown = true;
	apn->cfg.tx_gpdu_seq = true;
	INIT_LLIST_HEAD(&apn->cfg.name_list);

	llist_add_tail(&apn->list, &ggsn->apn_list);
	return apn;
}

/* GGSN Node */

static struct cmd_node ggsn_node = {
	GGSN_NODE,
	"%s(config-ggsn)# ",
	1,
};

DEFUN(cfg_ggsn, cfg_ggsn_cmd,
	"ggsn NAME",
	"Configure the Gateway GPRS Support Node\n" "GGSN Name (has only local significance)\n")
{
	struct ggsn_ctx *ggsn;

	ggsn = ggsn_find_or_create(tall_ggsn_ctx, argv[0]);
	if (!ggsn)
		return CMD_WARNING;

	vty->node = GGSN_NODE;
	vty->index = ggsn;
	vty->index_sub = &ggsn->cfg.description;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ggsn, cfg_no_ggsn_cmd,
	"no ggsn NAME",
	NO_STR "Remove the named Gateway GPRS Support Node\n"
	"GGSN Name (has only local significance)\n")
{
	struct ggsn_ctx *ggsn;

	ggsn = ggsn_find(argv[0]);
	if (!ggsn) {
		vty_out(vty, "%% No such GGSN '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!ggsn->cfg.shutdown) {
		vty_out(vty, "%% GGSN %s is still active, please shutdown first%s",
			ggsn->cfg.name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!llist_empty(&ggsn->apn_list)) {
		vty_out(vty, "%% GGSN %s still has APNs configured, please remove first%s",
			ggsn->cfg.name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_del(&ggsn->list);
	talloc_free(ggsn);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_bind_ip, cfg_ggsn_bind_ip_cmd,
	"gtp bind-ip A.B.C.D",
	"GTP Parameters\n"
	"Set the IP address for the local GTP bind\n"
	"IPv4 Address\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;
	size_t t;

	ippool_aton(&ggsn->cfg.listen_addr, &t, argv[0], 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_gtpc_ip, cfg_ggsn_gtpc_ip_cmd,
	"gtp control-ip A.B.C.D",
	"GTP Parameters\n"
	"Set the IP address states as local IP in GTP-C messages\n"
	"IPv4 Address\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;
	size_t t;

	ippool_aton(&ggsn->cfg.gtpc_addr, &t, argv[0], 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_gtpu_ip, cfg_ggsn_gtpu_ip_cmd,
	"gtp user-ip A.B.C.D",
	"GTP Parameters\n"
	"Set the IP address states as local IP in GTP-U messages\n"
	"IPv4 Address\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;
	size_t t;

	ippool_aton(&ggsn->cfg.gtpu_addr, &t, argv[0], 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_state_dir, cfg_ggsn_state_dir_cmd,
	"gtp state-dir PATH",
	"GTP Parameters\n"
	"Set the directory for the GTP State file\n"
	"Local Directory\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;

	osmo_talloc_replace_string(ggsn, &ggsn->cfg.state_dir, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_apn, cfg_ggsn_apn_cmd,
	"apn NAME", "APN Configuration\n" "APN Name\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;
	struct apn_ctx *apn;

	apn = ggsn_find_or_create_apn(ggsn, argv[0]);
	if (!apn)
		return CMD_WARNING;

	vty->node = APN_NODE;
	vty->index = apn;
	vty->index_sub = &ggsn->cfg.description;

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_no_apn, cfg_ggsn_no_apn_cmd,
	"no apn NAME",
	NO_STR "Remove APN Configuration\n" "APN Name\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;
	struct apn_ctx *apn;

	apn = ggsn_find_apn(ggsn, argv[0]);
	if (!apn) {
		vty_out(vty, "%% No such APN '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!apn->cfg.shutdown) {
		vty_out(vty, "%% APN %s still active, please shutdown first%s",
			apn->cfg.name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_del(&apn->list);
	talloc_free(apn);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_default_apn, cfg_ggsn_default_apn_cmd,
	"default-apn NAME",
	"Set a default-APN to be used if no other APN matches\n"
	"APN Name\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;
	struct apn_ctx *apn;

	apn = ggsn_find_apn(ggsn, argv[0]);
	if (!apn) {
		vty_out(vty, "%% No APN of name '%s' found%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ggsn->cfg.default_apn = apn;
	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_no_default_apn, cfg_ggsn_no_default_apn_cmd,
	"no default-apn",
	NO_STR "Remove default-APN to be used if no other APN matches\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;
	ggsn->cfg.default_apn = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_shutdown, cfg_ggsn_shutdown_cmd,
	"shutdown ggsn",
	"Put the GGSN in administrative shut-down\n" GGSN_STR)
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;

	if (!ggsn->cfg.shutdown) {
		if (ggsn_stop(ggsn)) {
			vty_out(vty, "%% Failed to shutdown GGSN%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		ggsn->cfg.shutdown = true;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_no_shutdown, cfg_ggsn_no_shutdown_cmd,
	"no shutdown ggsn",
	NO_STR GGSN_STR "Remove the GGSN from administrative shut-down\n")
{
	struct ggsn_ctx *ggsn = (struct ggsn_ctx *) vty->index;

	if (ggsn->cfg.shutdown) {
		if (ggsn_start(ggsn) < 0) {
			vty_out(vty, "%% Failed to start GGSN, check log for details%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		ggsn->cfg.shutdown = false;
	}

	return CMD_SUCCESS;
}

/* APN Node */

static struct cmd_node apn_node = {
	APN_NODE,
	"%s(config-ggsn-apn)# ",
	1,
};

static const struct value_string pdp_type_names[] = {
	{ APN_TYPE_IPv4, "v4" },
	{ APN_TYPE_IPv6, "v6" },
	{ APN_TYPE_IPv4v6, "v4v6" },
	{ 0, NULL }
};

static const struct value_string apn_gtpu_mode_names[] = {
	{ APN_GTPU_MODE_TUN,		"tun" },
	{ APN_GTPU_MODE_KERNEL_GTP,	"kernel-gtp" },
	{ 0, NULL }
};


#define V4V6V46_STRING	"IPv4(-only) PDP Type\n"	\
			"IPv6(-only) PDP Type\n"	\
			"IPv4v6 (dual-stack) PDP Type\n"

DEFUN(cfg_apn_type_support, cfg_apn_type_support_cmd,
	"type-support (v4|v6|v4v6)",
	"Enable support for PDP Type\n"
	V4V6V46_STRING)
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	uint32_t type = get_string_value(pdp_type_names, argv[0]);

	apn->cfg.apn_type_mask |= type;
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_type_support, cfg_apn_no_type_support_cmd,
	"no type-support (v4|v6|v4v6)",
	NO_STR "Disable support for PDP Type\n"
	V4V6V46_STRING)
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	uint32_t type = get_string_value(pdp_type_names, argv[0]);

	apn->cfg.apn_type_mask &= ~type;
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_gtpu_mode, cfg_apn_gtpu_mode_cmd,
	"gtpu-mode (tun|kernel-gtp)",
	"Set the Mode for this APN (tun or Linux Kernel GTP)\n"
	"GTP-U in userspace using TUN device\n"
	"GTP-U in kernel using Linux Kernel GTP\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;

	apn->cfg.gtpu_mode = get_string_value(apn_gtpu_mode_names, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_tun_dev_name, cfg_apn_tun_dev_name_cmd,
	"tun-device NAME",
	"Configure tun device name\n"
	"TUN device name")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	osmo_talloc_replace_string(apn, &apn->tun.cfg.dev_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ipup_script, cfg_apn_ipup_script_cmd,
	"ipup-script PATH",
	"Configure name/path of ip-up script\n"
	"File/Path name of ip-up script\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	osmo_talloc_replace_string(apn, &apn->tun.cfg.ipup_script, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_ipup_script, cfg_apn_no_ipup_script_cmd,
	"no ipup-script",
	NO_STR "Disable ip-up script\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	talloc_free(apn->tun.cfg.ipup_script);
	apn->tun.cfg.ipup_script = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ipdown_script, cfg_apn_ipdown_script_cmd,
	"ipdown-script PATH",
	"Configure name/path of ip-down script\n"
	"File/Path name of ip-down script\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	osmo_talloc_replace_string(apn, &apn->tun.cfg.ipdown_script, argv[0]);
	return CMD_SUCCESS;
}

/* convert prefix from "A.B.C.D/M" notation to in46_prefix */
static void str2prefix(struct in46_prefix *pfx, const char *in)
{
	size_t t;

	ippool_aton(&pfx->addr, &t, in, 0);
	pfx->prefixlen = t;
}

DEFUN(cfg_apn_no_ipdown_script, cfg_apn_no_ipdown_script_cmd,
	"no ipdown-script",
	NO_STR "Disable ip-down script\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	talloc_free(apn->tun.cfg.ipdown_script);
	apn->tun.cfg.ipdown_script = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ip_prefix, cfg_apn_ip_prefix_cmd,
	"ip prefix (static|dynamic) A.B.C.D/M",
	IP_STR PREFIX_STR "IPv4 Adress/Prefix-Length\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	struct in46_prefix *pfx;

	/* first update our parsed prefix */
	if (!strcmp(argv[0], "static"))
		pfx = &apn->v4.cfg.static_prefix;
	else
		pfx = &apn->v4.cfg.dynamic_prefix;
	str2prefix(pfx, argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ip_ifconfig, cfg_apn_ip_ifconfig_cmd,
	"ip ifconfig A.B.C.D/M",
	IP_STR IFCONFIG_STR "IPv4 Adress/Prefix-Length\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	str2prefix(&apn->v4.cfg.ifconfig_prefix, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_ip_ifconfig, cfg_apn_no_ip_ifconfig_cmd,
	"no ip ifconfig",
	NO_STR IP_STR IFCONFIG_STR)
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	memset(&apn->v4.cfg.ifconfig_prefix, 0, sizeof(apn->v4.cfg.ifconfig_prefix));
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ipv6_prefix, cfg_apn_ipv6_prefix_cmd,
	"ipv6 prefix (static|dynamic) X:X::X:X/M",
	IP6_STR PREFIX_STR "IPv6 Address/Prefix-Length\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	struct in46_prefix *pfx;

	if (!strcmp(argv[0], "static"))
		pfx = &apn->v6.cfg.static_prefix;
	else
		pfx = &apn->v6.cfg.dynamic_prefix;
	str2prefix(pfx, argv[1]);
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ipv6_ifconfig, cfg_apn_ipv6_ifconfig_cmd,
	"ipv6 ifconfig X:X::X:X/M",
	IP6_STR IFCONFIG_STR "IPv6 Adress/Prefix-Length\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	str2prefix(&apn->v6.cfg.ifconfig_prefix, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_ipv6_ifconfig, cfg_apn_no_ipv6_ifconfig_cmd,
	"no ipv6 ifconfig",
	NO_STR IP6_STR IFCONFIG_STR)
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	memset(&apn->v6.cfg.ifconfig_prefix, 0, sizeof(apn->v6.cfg.ifconfig_prefix));
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ipv6_linklocal, cfg_apn_ipv6_linklocal_cmd,
	"ipv6 link-local X:X::X:X/M",
	IP6_STR IFCONFIG_STR "IPv6 Link-local Adress/Prefix-Length\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	str2prefix(&apn->v6.cfg.ll_prefix, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_ipv6_linklocal, cfg_apn_no_ipv6_linklocal_cmd,
	"no ipv6 link-local",
	NO_STR IP6_STR IFCONFIG_STR)
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	memset(&apn->v6.cfg.ll_prefix, 0, sizeof(apn->v6.cfg.ll_prefix));
	return CMD_SUCCESS;
}

#define DNS_STRINGS "Configure DNS Server\n" "primary/secondary DNS\n" "IP address of DNS Sever\n"

DEFUN(cfg_apn_ip_dns, cfg_apn_ip_dns_cmd,
	"ip dns <0-1> A.B.C.D",
	IP_STR DNS_STRINGS)
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	int idx = atoi(argv[0]);
	size_t dummy;

	ippool_aton(&apn->v4.cfg.dns[idx], &dummy, argv[1], 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ipv6_dns, cfg_apn_ipv6_dns_cmd,
	"ipv6 dns <0-1> X:X::X:X",
	IP6_STR DNS_STRINGS)
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	int idx = atoi(argv[0]);
	size_t dummy;

	ippool_aton(&apn->v6.cfg.dns[idx], &dummy, argv[1], 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_dns, cfg_apn_no_dns_cmd,
	"no (ip|ipv6) dns <0-1>",
	NO_STR IP_STR IP6_STR "Disable DNS Server\n" "primary/secondary DNS\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	struct in46_addr *a;
	int idx = atoi(argv[1]);

	if (!strcmp(argv[0], "ip"))
		a = &apn->v4.cfg.dns[idx];
	else
		a = &apn->v6.cfg.dns[idx];

	memset(a, 0, sizeof(*a));

	return CMD_SUCCESS;
}

DEFUN(cfg_apn_gpdu_seq, cfg_apn_gpdu_seq_cmd,
	"g-pdu tx-sequence-numbers",
	"G-PDU Configuration\n" "Enable transmission of G-PDU sequence numbers\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	apn->cfg.tx_gpdu_seq = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_gpdu_seq, cfg_apn_no_gpdu_seq_cmd,
	"no g-pdu tx-sequence-numbers",
	NO_STR "G-PDU Configuration\n" "Disable transmission of G-PDU sequence numbers\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;
	apn->cfg.tx_gpdu_seq = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_shutdown, cfg_apn_shutdown_cmd,
	"shutdown",
	"Put the APN in administrative shut-down\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;

	if (!apn->cfg.shutdown) {
		if (apn_stop(apn)) {
			vty_out(vty, "%% Failed to Stop APN%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		apn->cfg.shutdown = true;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_apn_no_shutdown, cfg_apn_no_shutdown_cmd,
	"no shutdown",
	NO_STR "Remove the APN from administrative shut-down\n")
{
	struct apn_ctx *apn = (struct apn_ctx *) vty->index;

	if (apn->cfg.shutdown) {
		if (apn_start(apn) < 0) {
			vty_out(vty, "%% Failed to start APN, check log for details%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		apn->cfg.shutdown = false;
	}

	return CMD_SUCCESS;
}


static void vty_dump_prefix(struct vty *vty, const char *pre, const struct in46_prefix *pfx)
{
	vty_out(vty, "%s %s%s", pre, in46p_ntoa(pfx), VTY_NEWLINE);
}

static void config_write_apn(struct vty *vty, struct apn_ctx *apn)
{
	unsigned int i;

	vty_out(vty, " apn %s%s", apn->cfg.name, VTY_NEWLINE);
	if (apn->cfg.description)
		vty_out(vty, " description %s%s", apn->cfg.description, VTY_NEWLINE);
	vty_out(vty, "  gtpu-mode %s%s", get_value_string(apn_gtpu_mode_names, apn->cfg.gtpu_mode),
		VTY_NEWLINE);
	if (apn->tun.cfg.dev_name)
		vty_out(vty, "  tun-device %s%s", apn->tun.cfg.dev_name, VTY_NEWLINE);
	if (apn->tun.cfg.ipup_script)
		vty_out(vty, "  ipup-script %s%s", apn->tun.cfg.ipup_script, VTY_NEWLINE);
	if (apn->tun.cfg.ipdown_script)
		vty_out(vty, "  ipdown-script %s%s", apn->tun.cfg.ipdown_script, VTY_NEWLINE);

	for (i = 0; i < 32; i++) {
		if (!(apn->cfg.apn_type_mask & (1 << i)))
			continue;
		vty_out(vty, "  type-support %s%s", get_value_string(pdp_type_names, (1 << i)),
			VTY_NEWLINE);
	}

	if (!apn->cfg.tx_gpdu_seq)
		vty_out(vty, "  no g-pdu tx-sequence-numbers%s", VTY_NEWLINE);

	/* IPv4 prefixes + DNS */
	if (apn->v4.cfg.static_prefix.addr.len)
		vty_dump_prefix(vty, "  ip prefix static", &apn->v4.cfg.static_prefix);
	if (apn->v4.cfg.dynamic_prefix.addr.len)
		vty_dump_prefix(vty, "  ip prefix dynamic", &apn->v4.cfg.dynamic_prefix);
	for (i = 0; i < ARRAY_SIZE(apn->v4.cfg.dns); i++) {
		if (!apn->v4.cfg.dns[i].len)
			continue;
		vty_out(vty, "  ip dns %u %s%s", i, in46a_ntoa(&apn->v4.cfg.dns[i]), VTY_NEWLINE);
	}
	if (apn->v4.cfg.ifconfig_prefix.addr.len)
		vty_dump_prefix(vty, "  ip ifconfig", &apn->v4.cfg.ifconfig_prefix);

	/* IPv6 prefixes + DNS */
	if (apn->v6.cfg.static_prefix.addr.len)
		vty_dump_prefix(vty, "  ipv6 prefix static", &apn->v6.cfg.static_prefix);
	if (apn->v6.cfg.dynamic_prefix.addr.len)
		vty_dump_prefix(vty, "  ipv6 prefix dynamic", &apn->v6.cfg.dynamic_prefix);
	for (i = 0; i < ARRAY_SIZE(apn->v6.cfg.dns); i++) {
		if (!apn->v6.cfg.dns[i].len)
			continue;
		vty_out(vty, "  ipv6 dns %u %s%s", i, in46a_ntoa(&apn->v6.cfg.dns[i]), VTY_NEWLINE);
	}
	if (apn->v6.cfg.ifconfig_prefix.addr.len)
		vty_dump_prefix(vty, "  ipv6 ifconfig", &apn->v6.cfg.ifconfig_prefix);
	if (apn->v6.cfg.ll_prefix.addr.len)
		vty_dump_prefix(vty, "  ipv6 link-local", &apn->v6.cfg.ll_prefix);

	/* must be last */
	vty_out(vty, "  %sshutdown%s", apn->cfg.shutdown ? "" : "no ", VTY_NEWLINE);
}

static int config_write_ggsn(struct vty *vty)
{
	struct ggsn_ctx *ggsn;

	llist_for_each_entry(ggsn, &g_ggsn_list, list) {
		struct apn_ctx *apn;
		vty_out(vty, "ggsn %s%s", ggsn->cfg.name, VTY_NEWLINE);
		if (ggsn->cfg.description)
			vty_out(vty, " description %s%s", ggsn->cfg.description, VTY_NEWLINE);
		vty_out(vty, " gtp state-dir %s%s", ggsn->cfg.state_dir, VTY_NEWLINE);
		vty_out(vty, " gtp bind-ip %s%s", in46a_ntoa(&ggsn->cfg.listen_addr), VTY_NEWLINE);
		if (ggsn->cfg.gtpc_addr.v4.s_addr)
			vty_out(vty, " gtp control-ip %s%s", in46a_ntoa(&ggsn->cfg.gtpc_addr), VTY_NEWLINE);
		if (ggsn->cfg.gtpu_addr.v4.s_addr)
			vty_out(vty, " gtp user-ip %s%s", in46a_ntoa(&ggsn->cfg.gtpu_addr), VTY_NEWLINE);
		llist_for_each_entry(apn, &ggsn->apn_list, list)
			config_write_apn(vty, apn);
		if (ggsn->cfg.default_apn)
			vty_out(vty, " default-apn %s%s", ggsn->cfg.default_apn->cfg.name, VTY_NEWLINE);
		/* must be last */
		vty_out(vty, " %sshutdown ggsn%s", ggsn->cfg.shutdown ? "" : "no ", VTY_NEWLINE);
	}

	return 0;
}

static const char *print_gsnaddr(const struct ul16_t *in)
{
	struct in46_addr in46;

	in46.len = in->l;
	OSMO_ASSERT(in->l <= sizeof(in46.v6));
	memcpy(&in46.v6, in->v, in->l);

	return in46a_ntoa(&in46);
}

static void show_one_pdp(struct vty *vty, struct pdp_t *pdp)
{
	struct in46_addr eua46;
	char name_buf[256];
	char *apn_name;
	int rc;

	/* Attempt to decode MSISDN */
	rc = gsm48_decode_bcd_number2(name_buf, sizeof(name_buf),
				      pdp->msisdn.v, pdp->msisdn.l, 0);

	vty_out(vty, "IMSI: %s, NSAPI: %u, MSISDN: %s%s", imsi_gtp2str(&pdp->imsi), pdp->nsapi,
		rc ? "(NONE)" : name_buf, VTY_NEWLINE);

	vty_out(vty, " Control: %s:%08x ", print_gsnaddr(&pdp->gsnlc), pdp->teic_own);
	vty_out(vty, "<-> %s:%08x%s", print_gsnaddr(&pdp->gsnrc), pdp->teic_gn, VTY_NEWLINE);

	vty_out(vty, " Data: %s:%08x ", print_gsnaddr(&pdp->gsnlu), pdp->teid_own);
	vty_out(vty, "<-> %s:%08x%s", print_gsnaddr(&pdp->gsnru), pdp->teid_gn, VTY_NEWLINE);

	apn_name = osmo_apn_to_str(name_buf, pdp->apn_req.v, pdp->apn_req.l);
	vty_out(vty, " APN requested: %s%s", apn_name ? name_buf : "(NONE)", VTY_NEWLINE);
	apn_name = osmo_apn_to_str(name_buf, pdp->apn_use.v, pdp->apn_use.l);
	vty_out(vty, " APN in use: %s%s", apn_name ? name_buf : "(NONE)", VTY_NEWLINE);

	in46a_from_eua(&pdp->eua, &eua46);
	vty_out(vty, " End-User Address: %s%s", in46a_ntoa(&eua46), VTY_NEWLINE);
	vty_out(vty, " Transmit GTP Sequence Number for G-PDU: %s%s",
		pdp->tx_gpdu_seq ? "Yes" : "No", VTY_NEWLINE);
}

DEFUN(show_pdpctx_imsi, show_pdpctx_imsi_cmd,
	"show pdp-context imsi IMSI [<0-15>]",
	SHOW_STR "Display information on PDP Context\n"
	"PDP contexts for given IMSI\n"
	"PDP context for given NSAPI\n")
{
	uint64_t imsi = strtoull(argv[0], NULL, 10);
	unsigned int nsapi;
	struct pdp_t *pdp;
	int num_found = 0;

	if (argc > 1) {
		nsapi = atoi(argv[1]);
		if (pdp_getimsi(&pdp, imsi, nsapi)) {
			show_one_pdp(vty, pdp);
			num_found++;
		}
	} else {
		for (nsapi = 0; nsapi < PDP_MAXNSAPI; nsapi++) {
			if (pdp_getimsi(&pdp, imsi, nsapi))
				continue;
			show_one_pdp(vty, pdp);
			num_found++;
		}
	}
	if (num_found == 0) {
		vty_out(vty, "%% No such PDP context found%s", VTY_NEWLINE);
		return CMD_WARNING;
	} else
		return CMD_SUCCESS;
}

DEFUN(show_pdpctx_ip, show_pdpctx_ip_cmd,
	"show pdp-context ggsn NAME ipv4 A.B.C.D",
	SHOW_STR "Display information on PDP Context\n"
	GGSN_STR "GGSN Name\n" "IPv4 address type\n" "IP address\n")
{
	struct ggsn_ctx *ggsn;
	struct apn_ctx *apn;
	unsigned int i;

	ggsn = ggsn_find(argv[0]);
	if (!ggsn) {
		vty_out(vty, "%% No such GGSN '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Iterate over all APNs of a given GGSN */
	llist_for_each_entry(apn, &ggsn->apn_list, list) {
		struct ippool_t *pool = apn->v4.pool;

		/* In some rare cases, if GGSN fails to init TUN/TAP interfaces
		 * (e.g. due to insufficient permissions), it will continue to
		 * work in such broken state, and pool would be NULL. */
		if (!pool)
			continue;

		/* Iterate over all IPv4 pool members */
		for (i = 0; i < pool->listsize; i++) {
			struct ippoolm_t *member = &pool->member[i];
			if (member->inuse == 0)
				continue;
			if (strcmp(argv[1], in46a_ntoa(&member->addr)) == 0) {
				show_one_pdp(vty, member->peer);
				return CMD_SUCCESS;
			}
		}
	}

	vty_out(vty, "%% No PDP context found for IP '%s'%s", argv[1], VTY_NEWLINE);
	return CMD_WARNING;
}

/* show all (active) PDP contexts within a pool */
static void ippool_show_pdp_contexts(struct vty *vty, struct ippool_t *pool)
{
	unsigned int i;

	if (!pool)
		return;

	for (i = 0; i < pool->listsize; i++) {
		struct ippoolm_t *member = &pool->member[i];
		if (member->inuse == 0)
			continue;
		show_one_pdp(vty, member->peer);
	}
}

/* show all (active) PDP contexts within an APN */
static void apn_show_pdp_contexts(struct vty *vty, struct apn_ctx *apn)
{
	ippool_show_pdp_contexts(vty, apn->v4.pool);
	ippool_show_pdp_contexts(vty, apn->v6.pool);
}

DEFUN(show_pdpctx, show_pdpctx_cmd,
	"show pdp-context ggsn NAME",
	SHOW_STR "Show PDP Context Information\n"
	GGSN_STR "GGSN Name\n")
{
	struct ggsn_ctx *ggsn;
	struct apn_ctx *apn;

	ggsn = ggsn_find(argv[0]);
	if (!ggsn) {
		vty_out(vty, "%% No such GGSN '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_for_each_entry(apn, &ggsn->apn_list, list)
		apn_show_pdp_contexts(vty, apn);

	return CMD_SUCCESS;
}

DEFUN(show_pdpctx_apn, show_pdpctx_apn_cmd,
	"show pdp-context ggsn NAME apn APN",
	SHOW_STR "Show PDP Context Information\n"
	GGSN_STR "GGSN Name\n" "Filter by APN\n" "APN name\n")
{
	struct ggsn_ctx *ggsn;
	struct apn_ctx *apn;

	ggsn = ggsn_find(argv[0]);
	if (!ggsn) {
		vty_out(vty, "%% No such GGSN '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn = ggsn_find_apn(ggsn, argv[1]);
	if (!apn) {
		vty_out(vty, "%% No such APN '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	apn_show_pdp_contexts(vty, apn);
	return CMD_SUCCESS;
}

/* Backwards compatibility: the VTY parser is (mis)interpreting
 * "[apn APN]" as two separate elements: "[apn" and "APN]",
 * but the first part somehow turns into command "ap". */
ALIAS_DEPRECATED(show_pdpctx_apn, show_deprecated_pdpctx_apn_cmd,
		 "show pdp-context ggsn NAME ap APN",
		 SHOW_STR "Show PDP Context Information\n"
		 GGSN_STR "GGSN Name\n" "Filter by APN\n" "APN name\n");

static void show_apn(struct vty *vty, struct apn_ctx *apn)
{
	vty_out(vty, " APN: %s%s", apn->cfg.name, VTY_NEWLINE);
	/* FIXME */
}

static void show_one_ggsn(struct vty *vty, struct ggsn_ctx *ggsn)
{
	struct apn_ctx *apn;
	vty_out(vty, "GGSN %s: Bound to %s%s", ggsn->cfg.name, in46a_ntoa(&ggsn->cfg.listen_addr),
		VTY_NEWLINE);
	/* FIXME */

	llist_for_each_entry(apn, &ggsn->apn_list, list)
		show_apn(vty, apn);
}

DEFUN(show_ggsn, show_ggsn_cmd,
	"show ggsn [NAME]",
	SHOW_STR "Display information on the GGSN\n")
{
	struct ggsn_ctx *ggsn;

	if (argc == 0) {
		llist_for_each_entry(ggsn, &g_ggsn_list, list)
			show_one_ggsn(vty, ggsn);
	} else {
		ggsn = ggsn_find(argv[0]);
		if (!ggsn)
			return CMD_WARNING;
		show_one_ggsn(vty, ggsn);
	}

	return CMD_SUCCESS;
}

int ggsn_vty_init(void)
{
	install_element_ve(&show_pdpctx_cmd);
	install_element_ve(&show_pdpctx_apn_cmd);
	install_element_ve(&show_deprecated_pdpctx_apn_cmd);
	install_element_ve(&show_pdpctx_imsi_cmd);
	install_element_ve(&show_pdpctx_ip_cmd);
	install_element_ve(&show_ggsn_cmd);

	install_element(CONFIG_NODE, &cfg_ggsn_cmd);
	install_element(CONFIG_NODE, &cfg_no_ggsn_cmd);

	install_node(&ggsn_node, config_write_ggsn);
	install_element(GGSN_NODE, &cfg_description_cmd);
	install_element(GGSN_NODE, &cfg_no_description_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_shutdown_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_no_shutdown_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_bind_ip_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_gtpc_ip_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_gtpu_ip_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_state_dir_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_apn_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_no_apn_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_default_apn_cmd);
	install_element(GGSN_NODE, &cfg_ggsn_no_default_apn_cmd);

	install_node(&apn_node, NULL);
	install_element(APN_NODE, &cfg_description_cmd);
	install_element(APN_NODE, &cfg_no_description_cmd);
	install_element(APN_NODE, &cfg_apn_shutdown_cmd);
	install_element(APN_NODE, &cfg_apn_no_shutdown_cmd);
	install_element(APN_NODE, &cfg_apn_gtpu_mode_cmd);
	install_element(APN_NODE, &cfg_apn_type_support_cmd);
	install_element(APN_NODE, &cfg_apn_no_type_support_cmd);
	install_element(APN_NODE, &cfg_apn_tun_dev_name_cmd);
	install_element(APN_NODE, &cfg_apn_ipup_script_cmd);
	install_element(APN_NODE, &cfg_apn_no_ipup_script_cmd);
	install_element(APN_NODE, &cfg_apn_ipdown_script_cmd);
	install_element(APN_NODE, &cfg_apn_no_ipdown_script_cmd);
	install_element(APN_NODE, &cfg_apn_ip_prefix_cmd);
	install_element(APN_NODE, &cfg_apn_ipv6_prefix_cmd);
	install_element(APN_NODE, &cfg_apn_ip_dns_cmd);
	install_element(APN_NODE, &cfg_apn_ipv6_dns_cmd);
	install_element(APN_NODE, &cfg_apn_no_dns_cmd);
	install_element(APN_NODE, &cfg_apn_ip_ifconfig_cmd);
	install_element(APN_NODE, &cfg_apn_no_ip_ifconfig_cmd);
	install_element(APN_NODE, &cfg_apn_ipv6_ifconfig_cmd);
	install_element(APN_NODE, &cfg_apn_no_ipv6_ifconfig_cmd);
	install_element(APN_NODE, &cfg_apn_ipv6_linklocal_cmd);
	install_element(APN_NODE, &cfg_apn_no_ipv6_linklocal_cmd);
	install_element(APN_NODE, &cfg_apn_gpdu_seq_cmd);
	install_element(APN_NODE, &cfg_apn_no_gpdu_seq_cmd);

	return 0;
}

static int ggsn_vty_is_config_node(struct vty *vty, int node)
{
	switch (node) {
	case GGSN_NODE:
	case APN_NODE:
		return 1;
	default:
		return 0;
	}
}

static int ggsn_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case GGSN_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	case APN_NODE:
		vty->node = GGSN_NODE;
		{
			struct apn_ctx *apn = vty->index;
			vty->index = apn->ggsn;
			vty->index_sub = &apn->ggsn->cfg.description;
		}
		break;
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
	}

	return vty->node;
}

static const char ggsn_copyright[] =
	"Copyright (C) 2011-2017 Harald Welte <laforge@gnumonks.org>\r\n"
	"Copyright (C) 2012-2017 Holger Hans Peter Freyther <holger@moiji-mobile.com>\r\n"
	"Copyright (C) 2012-2017 sysmocom - s.f.m.c. GmbH\r\n"
	"Copyright (C) 2002-2005 Mondru AB\r\n"
	"License GPLv2: GNU GPL version 2 <http://gnu.org/licenses/gpl-2.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

struct vty_app_info g_vty_info = {
	.name		= "OsmoGGSN",
	.version	= PACKAGE_VERSION,
	.copyright	= ggsn_copyright,
	.go_parent_cb	= ggsn_vty_go_parent,
	.is_config_node	= ggsn_vty_is_config_node,
};
