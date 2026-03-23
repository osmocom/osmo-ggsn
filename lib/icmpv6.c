/* Minimal ICMPv6 code for generating router advertisements as required by
 * relevant 3GPP specs for a GGSN with IPv6 PDP contexts */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#if defined(__FreeBSD__)
#include <sys/types.h>	/* FreeBSD 10.x needs this before ip6.h */
#include <sys/endian.h>
#endif
#include <netinet/ip6.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <osmocom/netif/icmpv6.h>

#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/pdp.h>

#include "ippool.h"
#include "syserr.h"
#include "icmpv6.h"
#include "config.h"

/* Validate an ICMPv6 neighbor solicitation according to RFC4861 7.1.1 */
static bool icmpv6_validate_neigh_solicit(const uint8_t *pack, unsigned len)
{
	const struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;

	/* Hop limit field must have 255 */
	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim != 255)
		return false;
	/* FIXME: ICMP checksum is valid */
	/* ICMP length (derived from IP length) is 24 or more octets */
	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen < 24)
		return false;
	/* FIXME: All included options have a length > 0 */
	/* FIXME: If the IP source address is the unspecified address, the IP
	 * destination address is a solicited-node multicast address. */
	/* FIXME: If IP source is unspecified, no source link-layer addr option */
	return true;
}

/* handle incoming packets to the all-routers multicast address */
int handle_router_mcast(struct gsn_t *gsn, struct pdp_t *pdp,
			const struct in6_addr *pdp_prefix,
			const struct in6_addr *own_ll_addr,
			uint32_t mtu,
			const uint8_t *pack, unsigned len)
{
	const struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	const struct osmo_icmpv6_hdr *ic6h = (struct osmo_icmpv6_hdr *) (pack + sizeof(*ip6h));
	struct msgb *msg;

	if (len < sizeof(*ip6h)) {
		LOGP(DICMP6, LOGL_NOTICE, "Packet too short: %u bytes\n", len);
		return -1;
	}

	/* we only treat ICMPv6 here */
	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6) {
		LOGP(DICMP6, LOGL_DEBUG, "Ignoring non-ICMP to all-routers mcast\n");
		return 0;
	}

	if (len < sizeof(*ip6h) + sizeof(*ic6h)) {
		LOGP(DICMP6, LOGL_NOTICE, "Short ICMPv6 packet: %s\n", osmo_hexdump(pack, len));
		return -1;
	}

	switch (ic6h->type) {
	case 133:	/* router solicitation */
		if (ic6h->code != 0) {
			LOGP(DICMP6, LOGL_NOTICE, "ICMPv6 type 133 but code %d\n", ic6h->code);
			return -1;
		}
		if (!osmo_icmpv6_validate_router_solicit(pack, len)) {
			LOGP(DICMP6, LOGL_NOTICE, "Invalid Router Solicitation: %s\n",
				osmo_hexdump(pack, len));
			return -1;
		}
		/* Send router advertisement from GGSN link-local
		 * address to MS link-local address, including prefix
		 * allocated to this PDP context */
		msg = osmo_icmpv6_construct_ra(own_ll_addr, &ip6h->ip6_src, pdp_prefix, mtu);
		/* Send the constructed RA to the MS */
		gtp_data_req(gsn, pdp, msgb_data(msg), msgb_length(msg));
		msgb_free(msg);
		break;
	default:
		LOGP(DICMP6, LOGL_DEBUG, "Unknown ICMPv6 type %u\n", ic6h->type);
		break;
	}
	return 0;
}

/* handle incoming packets to the solicited-node multicast address */
int handle_solicited_node_mcast(const uint8_t *pack, unsigned len)
{
	const struct ip6_hdr *ip6h = (struct ip6_hdr *)pack;
	const struct osmo_icmpv6_hdr *ic6h = (struct osmo_icmpv6_hdr *) (pack + sizeof(*ip6h));

	if (len < sizeof(*ip6h)) {
		LOGP(DICMP6, LOGL_NOTICE, "Packet too short: %u bytes\n", len);
		return -1;
	}

	/* we only treat ICMPv6 here */
	if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6) {
		LOGP(DICMP6, LOGL_DEBUG, "Ignoring non-ICMP solicited-node mcast\n");
		return 0;
	}

	if (len < sizeof(*ip6h) + sizeof(*ic6h)) {
		LOGP(DICMP6, LOGL_NOTICE, "Short ICMPv6 packet: %s\n", osmo_hexdump(pack, len));
		return -1;
	}

	switch (ic6h->type) {
	case 135: /* Neighbor Solicitation. RFC2461, RFC2462 */
		if (ic6h->code != 0) {
			LOGP(DICMP6, LOGL_NOTICE, "ICMPv6 type 135 but code %d\n", ic6h->code);
			return -1;
		}
		if (!icmpv6_validate_neigh_solicit(pack, len)) {
			LOGP(DICMP6, LOGL_NOTICE, "Invalid Neighbor Solicitation: %s\n",
				osmo_hexdump(pack, len));
			return -1;
		}
		/* RFC 2462: Ignore Neighbor (Duplicate Address Detection) */
		LOGP(DICMP6, LOGL_DEBUG, "Ignoring Rx ICMPv6 Neighbor Soliciation: %s\n", osmo_hexdump(pack, len));
		break;
	default:
		LOGP(DICMP6, LOGL_DEBUG, "Unknown ICMPv6 type %u\n", ic6h->type);
		break;
	}
	return 0;
}
